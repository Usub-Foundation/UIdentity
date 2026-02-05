#include "uvent_transport.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>
#include <uvent/net/Socket.h>
#include <uvent/tasks/Awaitable.h>
#include <uvent/tasks/AwaitableFrame.h>

namespace keycloak::http
{

    using TcpClient = usub::uvent::net::Socket<
        usub::uvent::net::Proto::TCP,
        usub::uvent::net::Role::ACTIVE>;

    namespace
    {

        inline bool is_ws(unsigned char c) { return std::isspace(c) != 0; }

        inline std::string trim_copy(std::string_view sv)
        {
            while (!sv.empty() && is_ws(static_cast<unsigned char>(sv.front())))
                sv.remove_prefix(1);
            while (!sv.empty() && is_ws(static_cast<unsigned char>(sv.back())))
                sv.remove_suffix(1);
            return std::string(sv);
        }

        inline std::string to_lower_copy(std::string_view sv)
        {
            std::string out;
            out.reserve(sv.size());
            for (unsigned char c : sv)
                out.push_back(static_cast<char>(std::tolower(c)));
            return out;
        }

        inline bool iequals(std::string_view a, std::string_view b)
        {
            if (a.size() != b.size())
                return false;
            for (size_t i = 0; i < a.size(); ++i)
            {
                unsigned char ca = static_cast<unsigned char>(a[i]);
                unsigned char cb = static_cast<unsigned char>(b[i]);
                if (std::tolower(ca) != std::tolower(cb))
                    return false;
            }
            return true;
        }

        inline std::optional<std::string> header_get_ci(
            const std::unordered_map<std::string, std::string> &headers,
            std::string_view key)
        {
            for (const auto &[k, v] : headers)
            {
                if (iequals(k, key))
                    return v;
            }
            return std::nullopt;
        }

        inline bool header_has_ci(
            const std::unordered_map<std::string, std::string> &headers,
            std::string_view key)
        {
            return header_get_ci(headers, key).has_value();
        }

        inline void header_set_if_missing_ci(
            std::unordered_map<std::string, std::string> &headers,
            std::string key,
            std::string value)
        {
            if (!header_has_ci(headers, key))
            {
                headers.emplace(std::move(key), std::move(value));
            }
        }

        // Finds "\r\n\r\n" in a growing buffer, returns position or npos.
        inline size_t find_header_end(const std::string &s)
        {
            return s.find("\r\n\r\n");
        }

        // Parse integer safely from string_view (base 10).
        inline std::optional<size_t> parse_size_t_dec(std::string_view sv)
        {
            sv = std::string_view(trim_copy(sv));
            if (sv.empty())
                return std::nullopt;
            size_t out = 0;
            auto *b = sv.data();
            auto *e = sv.data() + sv.size();
            auto res = std::from_chars(b, e, out);
            if (res.ec != std::errc() || res.ptr != e)
                return std::nullopt;
            return out;
        }

        // Parse hex integer safely from line.
        inline std::optional<size_t> parse_size_t_hex(std::string_view sv)
        {
            // strip optional chunk extensions: "1a;ext=..."
            const auto semi = sv.find(';');
            if (semi != std::string_view::npos)
                sv = sv.substr(0, semi);
            sv = std::string_view(trim_copy(sv));
            if (sv.empty())
                return std::nullopt;

            size_t out = 0;
            auto *b = sv.data();
            auto *e = sv.data() + sv.size();
            auto res = std::from_chars(b, e, out, 16);
            if (res.ec != std::errc())
                return std::nullopt;
            return out;
        }

        // Decodes HTTP/1.1 chunked transfer encoding.
        // Input: chunked body bytes (exactly what comes after headers).
        // Output: decoded body or std::nullopt on parse error.
        inline std::optional<std::string> decode_chunked(std::string_view in)
        {
            std::string out;
            out.reserve(in.size()); // upper bound

            size_t pos = 0;
            auto need = [&](size_t n) -> bool
            { return pos + n <= in.size(); };

            while (true)
            {
                // Read chunk-size line: "<hex>\r\n"
                const size_t line_end = in.find("\r\n", pos);
                if (line_end == std::string_view::npos)
                    return std::nullopt;

                const std::string_view size_line = in.substr(pos, line_end - pos);
                pos = line_end + 2;

                auto chunk_sz_opt = parse_size_t_hex(size_line);
                if (!chunk_sz_opt)
                    return std::nullopt;
                const size_t chunk_sz = *chunk_sz_opt;

                if (chunk_sz == 0)
                {
                    // Final chunk. After this: optional trailers then "\r\n"
                    // Consume trailer headers until empty line.
                    while (true)
                    {
                        const size_t t_end = in.find("\r\n", pos);
                        if (t_end == std::string_view::npos)
                            return std::nullopt;
                        if (t_end == pos)
                        {
                            pos += 2; // empty line
                            return out;
                        }
                        pos = t_end + 2; // skip trailer line
                    }
                }

                if (!need(chunk_sz + 2))
                    return std::nullopt; // chunk-data + "\r\n"

                out.append(in.data() + pos, chunk_sz);
                pos += chunk_sz;

                // Expect CRLF after chunk data
                if (in.substr(pos, 2) != "\r\n")
                    return std::nullopt;
                pos += 2;
            }
        }

    } // namespace

    void UventTransport::apply_defaults(std::unordered_map<std::string, std::string> &hdrs)
    {
        // Keep semantics simple: read body by Content-Length if available, else until EOF.
        // Force close to avoid keeping sockets and to avoid partial reads in early version.
        header_set_if_missing_ci(hdrs, "Connection", "close");

        // Helpful defaults for Keycloak:
        header_set_if_missing_ci(hdrs, "Accept", "application/json");
        // Avoid gzip/br:
        header_set_if_missing_ci(hdrs, "Accept-Encoding", "identity");
    }

    // TODO: support https
    std::string UventTransport::build_http1_request(
        std::string_view method,
        std::string_view request_target,
        std::string_view host,
        std::string_view port,
        std::string_view body,
        const std::unordered_map<std::string, std::string> &headers)
    {
        std::ostringstream req;
        req << method << " " << request_target << " HTTP/1.1\r\n";

        // Host header
        req << "Host: " << host;
        if (!port.empty())
            req << ":" << port;
        req << "\r\n";

        bool has_content_length = header_has_ci(headers, "Content-Length");

        for (const auto &[k, v] : headers)
        {
            req << k << ": " << v << "\r\n";
        }

        // Always send Content-Length for POST/PUT etc. Even for empty body, Content-Length: 0 is safe.
        if (!has_content_length)
        {
            req << "Content-Length: " << body.size() << "\r\n";
        }

        req << "\r\n";
        req << body;
        return req.str();
    }

    Response UventTransport::parse_http1_response(std::string_view raw)
    {
        Response r;
        r.status_code = 0;

        const auto split = raw.find("\r\n\r\n");
        if (split == std::string_view::npos)
        {
            r.body = "invalid_http_response_no_header_terminator";
            return r;
        }

        const std::string_view head = raw.substr(0, split);
        const std::string_view body = raw.substr(split + 4);

        std::istringstream iss(std::string(head));

        std::string httpver;
        if (!(iss >> httpver >> r.status_code))
        {
            r.status_code = 0;
            r.body = "invalid_http_status_line";
            return r;
        }

        std::string tmp;
        std::getline(iss, tmp);

        // Headers
        std::string line;
        while (std::getline(iss, line))
        {
            if (!line.empty() && line.back() == '\r')
                line.pop_back();
            if (line.empty())
                continue;

            const auto sep = line.find(':');
            if (sep == std::string::npos)
                continue;

            const std::string name = trim_copy(std::string_view(line).substr(0, sep));
            const std::string val = trim_copy(std::string_view(line).substr(sep + 1));
            if (!name.empty())
            {
                r.headers.emplace(name, val);
            }
        }

        // Decode body if needed
        const auto te = header_get_ci(r.headers, "Transfer-Encoding");
        if (te && iequals(trim_copy(*te), "chunked"))
        {
            auto decoded = decode_chunked(body);
            if (!decoded)
            {
                r.body = "chunked_decode_failed";
                return r;
            }
            r.body = std::move(*decoded);
            return r;
        }

        // Otherwise body is raw as-is (identity encoding expected)
        r.body.assign(body.begin(), body.end());
        return r;
    }

    usub::uvent::task::Awaitable<Response, usub::uvent::detail::AwaitableFrame<Response>>
    UventTransport::async_send_request(
        std::string_view host,
        std::string_view port,
        std::string_view method,
        std::string_view path,
        std::string_view body,
        const std::unordered_map<std::string, std::string> &headers_in)
    {
        // TODO:HTTPS

        std::unordered_map<std::string, std::string> headers = headers_in;
        apply_defaults(headers);

        // Connect target: proxy or direct
        const std::string connect_host = proxy_config_.is_enabled() ? proxy_config_.host : std::string(host);
        const std::string connect_port = proxy_config_.is_enabled()
                                             ? std::to_string(proxy_config_.port)
                                             : std::string(port);

        // Request target:
        // - if plain HTTP proxy, use absolute-form: http://host[:port]/path
        // - else use origin-form: /path?query
        std::string request_target;
        if (proxy_config_.is_enabled())
        {
            std::ostringstream abs;
            abs << "http://" << host;
            if (!port.empty())
                abs << ":" << port;
            abs << path;
            request_target = abs.str();
        }
        else
        {
            request_target = std::string(path);
        }

        const std::string request = build_http1_request(
            method, request_target, host, port, body, headers);

        TcpClient sock;

        // Connect
        {
            auto err = co_await sock.async_connect(connect_host, connect_port, connect_timeout_);
            if (err.has_value())
            {
                Response r;
                r.status_code = 0;
                r.body = "connect_failed";
                co_return r;
            }
        }

        // Apply IO timeout
        sock.set_timeout_ms(static_cast<timeout_t>(io_timeout_.count()));

        // Write all
        {
            size_t off = 0;
            const auto *data = reinterpret_cast<const uint8_t *>(request.data());
            const size_t sz = request.size();

            while (off < sz)
            {
                auto *p = const_cast<uint8_t *>(data + off);
                const size_t remaining = sz - off;

                ssize_t n = co_await sock.async_write(p, remaining);
                if (n <= 0)
                {
                    Response r;
                    r.status_code = 0;
                    r.body = "write_failed";
                    co_return r;
                }
                off += static_cast<size_t>(n);
            }
        }

        std::string raw;
        raw.reserve(8192);

        std::vector<uint8_t> buf(16 * 1024);

        while (find_header_end(raw) == std::string::npos)
        {
            ssize_t n = co_await sock.async_read(buf.data(), buf.size());
            if (n < 0)
            {
                Response r;
                r.status_code = 0;
                r.body = "read_failed";
                co_return r;
            }
            if (n == 0)
                break;
            raw.append(reinterpret_cast<const char *>(buf.data()), static_cast<size_t>(n));
            if (raw.size() > max_response_bytes_)
            {
                Response r;
                r.status_code = 0;
                r.body = "response_too_large";
                co_return r;
            }
        }

        const size_t hdr_end = find_header_end(raw);
        if (hdr_end == std::string::npos)
        {
            Response r;
            r.status_code = 0;
            r.body = "invalid_http_response_no_header_terminator";
            co_return r;
        }

        const std::string_view head_sv(raw.data(), hdr_end);

        std::unordered_map<std::string, std::string> hdrs_ci; // store lowercase keys
        {
            std::istringstream iss(std::string(head_sv));
            std::string httpver;
            long status = 0;
            iss >> httpver >> status;
            std::string line;
            std::getline(iss, line);
            while (std::getline(iss, line))
            {
                if (!line.empty() && line.back() == '\r')
                    line.pop_back();
                if (line.empty())
                    continue;
                const auto sep = line.find(':');
                if (sep == std::string::npos)
                    continue;

                std::string k = to_lower_copy(trim_copy(std::string_view(line).substr(0, sep)));
                std::string v = trim_copy(std::string_view(line).substr(sep + 1));
                if (!k.empty())
                    hdrs_ci.emplace(std::move(k), std::move(v));
            }
        }

        const size_t body_start = hdr_end + 4;
        const size_t already_have_body = raw.size() > body_start ? (raw.size() - body_start) : 0;

        // If Content-Length present AND not chunked, read exact bytes.
        const auto te_it = hdrs_ci.find("transfer-encoding");
        const bool is_chunked = (te_it != hdrs_ci.end()) && iequals(trim_copy(te_it->second), "chunked");

        if (!is_chunked)
        {
            const auto cl_it = hdrs_ci.find("content-length");
            if (cl_it != hdrs_ci.end())
            {
                auto len_opt = parse_size_t_dec(cl_it->second);
                if (!len_opt)
                {
                }
                else
                {
                    const size_t want = *len_opt;

                    while (already_have_body + (raw.size() - body_start - already_have_body) < want)
                    {
                        const size_t have = raw.size() > body_start ? (raw.size() - body_start) : 0;
                        if (have >= want)
                            break;

                        ssize_t n = co_await sock.async_read(buf.data(), buf.size());
                        if (n < 0)
                        {
                            Response r;
                            r.status_code = 0;
                            r.body = "read_failed";
                            co_return r;
                        }
                        if (n == 0)
                            break;
                        raw.append(reinterpret_cast<const char *>(buf.data()), static_cast<size_t>(n));

                        if (raw.size() > max_response_bytes_)
                        {
                            Response r;
                            r.status_code = 0;
                            r.body = "response_too_large";
                            co_return r;
                        }
                    }

                    co_return parse_http1_response(raw);
                }
            }
        }

        for (;;)
        {
            ssize_t n = co_await sock.async_read(buf.data(), buf.size());
            if (n < 0)
            {
                Response r;
                r.status_code = 0;
                r.body = "read_failed";
                co_return r;
            }
            if (n == 0)
                break;
            raw.append(reinterpret_cast<const char *>(buf.data()), static_cast<size_t>(n));

            if (raw.size() > max_response_bytes_)
            {
                Response r;
                r.status_code = 0;
                r.body = "response_too_large";
                co_return r;
            }
        }

        co_return parse_http1_response(raw);
    }

} // namespace keycloak::http
