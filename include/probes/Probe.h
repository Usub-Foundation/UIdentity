#pragma once

#include <atomic>

#include <unet/http.hpp>

namespace probes {

inline std::atomic_bool running{true};

class ProbeHandler {
public:
    ProbeHandler() = default;

    ServerHandler liveness(usub::unet::http::Request &request, usub::unet::http::Response &response);
    ServerHandler readiness(usub::unet::http::Request &request, usub::unet::http::Response &response);
    ServerHandler startup(usub::unet::http::Request &request, usub::unet::http::Response &response);
};

} // namespace probes
