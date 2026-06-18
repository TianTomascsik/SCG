// client.cpp — round-trip demo for the SCG C++ header-only wrapper.
//
// Build (after `cargo build -p scg-client`):
//   the simplest way is the Makefile one directory up:
//     cd .. && make cpp_client
//   or compile directly from this directory:
//     c++ -std=c++17 -I../../include client.cpp -L../../../../target/debug -lscg_client -o cpp_client
//
// Usage:
//   ./cpp_client <app_id> <uds|shm> <normal|safety> [mgmt_socket] [message]
//
// Requires a running gateway with a matching rule. Exits non-zero on error.

#include "scg_client.hpp"

#include <cstring>
#include <iostream>
#include <string>

static scg::Transport transport_from(const std::string& s) {
    if (s == "uds") return scg::Transport::Uds;
    if (s == "shm") return scg::Transport::Shm;
    throw scg::Error("invalid transport: " + s);
}

static scg::TrafficClass class_from(const std::string& s) {
    if (s == "normal") return scg::TrafficClass::Normal;
    if (s == "safety") return scg::TrafficClass::Safety;
    throw scg::Error("invalid class: " + s);
}

int main(int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "usage: " << argv[0]
                  << " <app_id> <uds|shm> <normal|safety> [mgmt_socket] [message]\n";
        return 2;
    }

    try {
        const std::string app_id = argv[1];
        const scg::Transport transport = transport_from(argv[2]);
        const scg::TrafficClass traffic_class = class_from(argv[3]);
        const std::string mgmt = (argc > 4) ? argv[4] : "";
        const std::string message = (argc > 5) ? argv[5] : "hello from C++";

        scg::Client client = scg::Client::connect(
            app_id, transport, traffic_class, scg::Direction::Encrypt, mgmt);
        std::cout << "connected\n";

        client.send(1, message);
        std::cout << "sent " << message.size() << " bytes\n";

        auto reply = client.recv_timeout(5000);
        if (!reply) {
            std::cerr << "recv timed out\n";
            return 1;
        }
        const auto& [traffic_id, payload] = *reply;
        std::cout << "recv: traffic_id=" << traffic_id << ' ' << payload.size()
                  << " bytes: "
                  << std::string(payload.begin(), payload.end()) << '\n';

        client.close();
        std::cout << "closed\n";
        return 0;
    } catch (const scg::Error& e) {
        std::cerr << "error: " << e.what() << '\n';
        return 1;
    }
}
