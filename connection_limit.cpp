//
// Created by avijeet on 18/3/24.
//
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <optional>

#include <exanic/exanic.h>
#include <exanic/fifo_tx.h>
#include <exasock/extensions.h>

int reserve_exanic_rx_buffer_for_connection(int fd, size_t size) {
    char dev[16];
    int port;
    if (exasock_tcp_get_device(fd, dev, sizeof(dev), &port) == -1) {
        std::cerr << "exasock_tcp_get_device() error. " << strerror(errno) << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "exanic tcp device " << dev << "\nport: " << port << '\n';
    exanic_t* exanic = exanic_acquire_handle(dev);
    if (exanic == nullptr) {
        std::cerr << "exanic_acquire_handle() error. " << exanic_get_last_error() << '\n';
        return EXIT_FAILURE;
    }
    exanic_tx_t* tx = exanic_acquire_tx_buffer(exanic, port, size);
    if (tx == nullptr) {
        std::cerr << "exanic_acquire_tx_buffer() error. " << exanic_get_last_error() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

std::optional<int> create_connection_to(const char* server_ip, int server_port) {
    sockaddr_in sa{};
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        std::cerr << "socket() failed. " << strerror(errno) << '\n';
        return std::nullopt;
    }
    std::cout << "socket created\n";

    std::memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_aton(server_ip, &sa.sin_addr);
    sa.sin_port = htons(server_port);

    if (connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa))) {
        std::cerr << "connect() failed. " << strerror(errno) << '\n';
        return std::nullopt;
    }
    std::cout << "connected to " << server_ip << ':' << server_port << '\n';

    int one = 1;
    if (setsockopt(fd, SOL_TCP, TCP_NODELAY, &one, sizeof(one)) < 0) {
        std::cerr << "setsockopt() error. " << strerror(errno) << '\n';
        return std::nullopt;
    }
    if (reserve_exanic_rx_buffer_for_connection(fd, 4 * 1024) == EXIT_FAILURE) {
        return std::nullopt;
    }
    return fd;
}

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "Required arguments: [SERVER IP], [SERVER PORT]\n";
        return EXIT_FAILURE;
    }

    const char* server_ip = argv[1];
    int server_port = std::stoi(argv[2]);
    std::vector<int> fds;

    while (true) {
        auto fd = create_connection_to(server_ip, server_port);
        if (fd.has_value()) {
            fds.push_back(fd.value());
            std::cout << fds.size() << " connections opened.\n";
        } else {
            break;
        }
    }
}