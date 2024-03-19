//
// Created by avijeet on 1/3/24.
//

#ifndef EXANIC_TCP_REPRO_UTIL_HPP

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <chrono>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <numeric>
#include <string>
#include <vector>
#include <thread>

#include <exanic/exanic.h>
#include <exanic/fifo_tx.h>
#include <exasock/extensions.h>

std::pair<exanic*, exanic_tx_t*> reserve_exanic_rx_buffer_for_connection(int fd, size_t size) {
    char dev[16];
    int port;
    if (exasock_tcp_get_device(fd, dev, sizeof(dev), &port) == -1) {
        std::cerr << "exasock_tcp_get_device() error. " << strerror(errno) << '\n';
        return {nullptr, nullptr};
    }
    std::cout << "exanic tcp device " << dev << "\nport: " << port << '\n';
    exanic_t* exanic = exanic_acquire_handle(dev);
    if (exanic == nullptr) {
        std::cerr << "exanic_acquire_handle() error. " << exanic_get_last_error() << '\n';
        return {nullptr, nullptr};
    }
    exanic_tx_t* tx = exanic_acquire_tx_buffer(exanic, port, size);
    if (tx == nullptr) {
        std::cerr << "exanic_acquire_tx_buffer() error. " << exanic_get_last_error() << '\n';
        return {nullptr, nullptr};
    }
    return {exanic, tx};
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
        std::cerr << "connect() failed. " << strerror(errno);
        return std::nullopt;
    }
    std::cout << "connected to " << server_ip << ':' << server_port << '\n';

    int one = 1;
    if (setsockopt(fd, SOL_TCP, TCP_NODELAY, &one, sizeof(one)) < 0) {
        std::cerr << "setsockopt() error. " << strerror(errno) << '\n';
        return std::nullopt;
    }
    return fd;
}

template <class T>
__attribute__((always_inline)) inline void DoNotOptimize(T &value) {
    asm volatile("" : "+rm" (const_cast<T&>(value)));
}

[[gnu::always_inline]] inline
size_t send_packet(int fd, const char* packet, size_t packet_size) {
    size_t bytes_sent = 0;
    do {
        size_t sent = send(fd, packet + bytes_sent, packet_size - bytes_sent, 0);
        if (sent == -1) {
            std::cerr << "send() error. " << strerror(errno) << '\n';
            std::this_thread::sleep_for(std::chrono::hours(1));
        }
        bytes_sent += sent;
    } while (bytes_sent < packet_size);
    return bytes_sent;
}

[[gnu::always_inline]] inline
int send_packet_exanic(exanic_tx_t* tx, int fd, char* frame, const char* packet, size_t packet_size) {
    ssize_t header_len = -1;
    do {
        header_len = exasock_tcp_build_header(fd, frame, 1024, 0, 0);
    } while (header_len == -1 and errno == EAGAIN);
    if (header_len == -1) {
        std::cerr << "exasock_tcp_build_header() error. " << strerror(errno) << '\n';
        return EXIT_FAILURE;
    }
    exasock_tcp_set_length(frame, header_len, packet_size);
    exasock_tcp_calc_checksum(frame, header_len, frame + header_len, packet_size);

    int bytes_sent = exanic_transmit_frame(tx, frame, header_len + packet_size);
    if (bytes_sent == -1) {
        std::cerr << "exanic_transmit_frame() error. " << exanic_get_last_error() << '\n';
        return bytes_sent;
    }
    if (exasock_tcp_send_advance(fd, packet, packet_size) == -1) {
        std::cerr << "exasock_tcp_send_advance() error. " << strerror(errno) << '\n';
        return -1;
    }

    return bytes_sent;
}

template<typename T>
void busy_wait_for(const T& t) {
    auto start = std::chrono::steady_clock::now();
    auto end = start + t;
    while (true) {
        if (std::chrono::steady_clock::now() > end) {
            break;
        }
    }
}

template<typename T>
inline void print_stats(std::vector<T>& cycles) {
    std::sort(cycles.begin(), cycles.end());
    auto n = cycles.size();
    auto total = std::accumulate(cycles.begin(), cycles.end(), 0ull);
    double mean = static_cast<double>(total) / n;
    auto min = *std::min_element(cycles.begin(), cycles.end());
    auto max = *std::max_element(cycles.begin(), cycles.end());
    std::transform(cycles.begin(), cycles.end(), cycles.begin(), [mean](double value){
        return ((value - mean)*(value - mean));
    });
    double std_dev = std::sqrt(std::accumulate(cycles.begin(), cycles.end(), 0.0) / n);
    std::cout << std::fixed << "Packets transmitted: " << n << "\nMean: " << mean << "\nMin: " << min << "\nMax: " << max << "\nstd-dev: " << std_dev << '\n';
}

template<typename T>
void dump_csv(std::vector<T>& cycles, int client_num, const std::string& filename) {
    std::ofstream out(filename + '_' + std::to_string(client_num) + ".csv");
    out << "time\n";
    for (auto i : cycles) {
        out << i << '\n';
    }
}

#define EXANIC_TCP_REPRO_UTIL_HPP

#endif //EXANIC_TCP_REPRO_UTIL_HPP
