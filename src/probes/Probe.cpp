#include "probes/Probe.h"

namespace probes {

ServerHandler ProbeHandler::liveness(usub::unet::http::Request &request, usub::unet::http::Response &response) {
    (void) request;
    response.setStatus(204);
    co_return;
}

ServerHandler ProbeHandler::readiness(usub::unet::http::Request &request, usub::unet::http::Response &response) {
    (void) request;

    if (!running.load(std::memory_order_acquire)) {
        response.setStatus(503);
        response.addHeader("Content-Type", "application/json");
        response.setBody(R"({"status":"starting"})");
        co_return;
    }

    response.setStatus(204);
    co_return;
}

ServerHandler ProbeHandler::startup(usub::unet::http::Request &request, usub::unet::http::Response &response) {
    (void) request;

    if (!running.load(std::memory_order_acquire)) {
        response.setStatus(503);
        response.addHeader("Content-Type", "application/json");
        response.setBody(R"({"status":"starting"})");
        co_return;
    }

    response.setStatus(204);
    co_return;
}

} // namespace probes
