// scg_client.hpp — header-only C++ RAII wrapper around the C ABI.
//
// This header has no source file: include it and link against
// `libscg_client.so` (or `libscg_client.a`). It wraps the opaque
// `ScgClientHandle*` in a move-only `scg::Client` that frees itself on scope
// exit and turns error codes into `scg::Error` exceptions.
//
//   #include "scg_client.hpp"
//   auto c = scg::Client::connect("app-telemetry", scg::Transport::Uds,
//                                  scg::TrafficClass::Safety,
//                                  scg::Direction::Encrypt);
//   c.send(1, std::string("hello"));
//   auto [traffic_id, payload] = c.recv();
//
#ifndef SCG_CLIENT_HPP
#define SCG_CLIENT_HPP

#include "scg_client.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace scg {

/// Transport selector (mirrors the C `SCG_TRANSPORT_*` constants).
enum class Transport : int {
    Uds = SCG_TRANSPORT_UDS,
    Shm = SCG_TRANSPORT_SHM,
};

/// Traffic class (mirrors the C `SCG_CLASS_*` constants).
enum class TrafficClass : int {
    Normal = SCG_CLASS_NORMAL,
    Safety = SCG_CLASS_SAFETY,
};

/// Pipeline direction (mirrors the C `SCG_DIRECTION_*` constants).
enum class Direction : int {
    Encrypt = SCG_DIRECTION_ENCRYPT,
    Decrypt = SCG_DIRECTION_DECRYPT,
};

/// Exception carrying a gateway/client error message.
class Error : public std::runtime_error {
public:
    explicit Error(const std::string& message) : std::runtime_error(message) {}
};

/// A received message: (traffic_id, payload).
using Message = std::pair<uint32_t, std::vector<uint8_t>>;

/// Move-only RAII handle for an SCG client endpoint.
class Client {
public:
    /// Create an endpoint and connect its data plane.
    ///
    /// `mgmt_socket` empty selects the default management socket path.
    /// Throws `scg::Error` on failure.
    static Client connect(const std::string& app_id,
                          Transport transport,
                          TrafficClass traffic_class,
                          Direction direction,
                          const std::string& mgmt_socket = std::string()) {
        char err[256] = {0};
        const char* mgmt = mgmt_socket.empty() ? nullptr : mgmt_socket.c_str();
        ScgClientHandle* handle = scg_client_connect(
            mgmt, app_id.c_str(), static_cast<int>(transport),
            static_cast<int>(traffic_class), static_cast<int>(direction), err,
            sizeof(err));
        if (handle == nullptr) {
            throw Error(err[0] != '\0' ? std::string(err)
                                       : std::string("scg_client_connect failed"));
        }
        return Client(handle);
    }

    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    Client(Client&& other) noexcept : handle_(other.handle_) {
        other.handle_ = nullptr;
    }
    Client& operator=(Client&& other) noexcept {
        if (this != &other) {
            reset();
            handle_ = other.handle_;
            other.handle_ = nullptr;
        }
        return *this;
    }

    ~Client() { reset(); }

    /// Send `len` bytes tagged with `traffic_id`. Throws on failure.
    void send(uint32_t traffic_id, const uint8_t* data, std::size_t len) {
        if (scg_client_send(handle_, traffic_id, data, len) != SCG_OK) {
            throw Error(last_error());
        }
    }
    void send(uint32_t traffic_id, const std::vector<uint8_t>& data) {
        send(traffic_id, data.data(), data.size());
    }
    void send(uint32_t traffic_id, const std::string& data) {
        send(traffic_id, reinterpret_cast<const uint8_t*>(data.data()),
             data.size());
    }

    /// Block until a message arrives. Throws on error.
    Message recv() {
        std::optional<Message> message = recv_timeout(-1);
        if (!message) {
            throw Error("recv returned no message");
        }
        return std::move(*message);
    }

    /// Wait up to `timeout_ms` (negative blocks). Returns `std::nullopt` on
    /// timeout; throws on error.
    std::optional<Message> recv_timeout(int timeout_ms) {
        uint32_t traffic_id = 0;
        uint8_t* buffer = nullptr;
        std::size_t len = 0;
        int rc = scg_client_recv(handle_, &traffic_id, &buffer, &len, timeout_ms);
        if (rc == SCG_TIMEOUT) {
            return std::nullopt;
        }
        if (rc != SCG_OK) {
            throw Error(last_error());
        }
        std::vector<uint8_t> payload(buffer, buffer + len);
        scg_client_free_buf(buffer, len);
        return std::optional<Message>(
            std::in_place, traffic_id, std::move(payload));
    }

    /// Deregister and free the endpoint. Idempotent; also run by the destructor.
    void close() { reset(); }

private:
    explicit Client(ScgClientHandle* handle) : handle_(handle) {}

    void reset() {
        if (handle_ != nullptr) {
            scg_client_close(handle_);
            handle_ = nullptr;
        }
    }

    std::string last_error() const {
        const char* msg = handle_ ? scg_client_last_error(handle_) : nullptr;
        return msg ? std::string(msg) : std::string("unknown error");
    }

    ScgClientHandle* handle_ = nullptr;
};

}  // namespace scg

#endif  // SCG_CLIENT_HPP
