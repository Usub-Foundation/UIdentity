#pragma once

#include <atomic>
#include <exception>
#include <source_location>
#include <string>

#include <ulog/ulog.h>
#include <unet/http.hpp>

namespace probes {

inline std::string make_location_string(
        const std::source_location &location = std::source_location::current()) {
    return std::string{location.file_name()} + ":" + std::to_string(location.line()) +
           " " + location.function_name();
}

class ProbeHandler {
public:
    explicit ProbeHandler(std::atomic<bool> &running) : running_(running) {}

    ServerHandler liveness(usub::unet::http::Request &, usub::unet::http::Response &response) {
        try {
            response.setStatus(204);
            co_return;
        } catch (const std::exception &e) {
            usub::ulog::critical("Probe failed in: {}: {}", make_location_string(), e.what());
        } catch (...) {
            usub::ulog::critical("Probe failed in: {}", make_location_string());
        }

        response.setStatus(500);
        co_return;
    }

    ServerHandler readiness(usub::unet::http::Request &, usub::unet::http::Response &response) {
        try {
            if (!running_.load(std::memory_order_acquire)) {
                response.setStatus(503);
                response.metadata.status_message = "Service Starting";
                response.addHeader("Content-Type", "application/json");
                response.setBody(R"({"status":"starting"})");
                co_return;
            }

            response.setStatus(204);
            co_return;
        } catch (const std::exception &e) {
            usub::ulog::critical("Probe failed in: {}: {}", make_location_string(), e.what());
        } catch (...) {
            usub::ulog::critical("Probe failed in: {}", make_location_string());
        }

        response.setStatus(500);
        co_return;
    }

    ServerHandler startup(usub::unet::http::Request &, usub::unet::http::Response &response) {
        try {
            if (!running_.load(std::memory_order_acquire)) {
                response.setStatus(503);
                response.metadata.status_message = "Service Starting";
                response.addHeader("Content-Type", "application/json");
                response.setBody(R"({"status":"starting"})");
                co_return;
            }

            response.setStatus(204);
            co_return;
        } catch (const std::exception &e) {
            usub::ulog::critical("Probe failed in: {}: {}", make_location_string(), e.what());
        } catch (...) {
            usub::ulog::critical("Probe failed in: {}", make_location_string());
        }

        response.setStatus(500);
        co_return;
    }

private:
    std::atomic<bool> &running_;
};

} // namespace probes
