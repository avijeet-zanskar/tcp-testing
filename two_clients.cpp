//
// Created by avijeet on 13/3/24.
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

#include "packet.hpp"
#include "util.hpp"

#include <exasock/socket.h>

[[gnu::always_inline]] inline
void send_packet(int fd, const char* packet, int packet_size) {
    int bytes_sent = 0;
    do {
        int sent = send(fd, packet + bytes_sent, packet_size - bytes_sent, 0);
        if (sent == -1) {
            std::cerr << "send() error. " << strerror(errno) << '\n';
            std::this_thread::sleep_for(std::chrono::hours(1));
        }
        bytes_sent += sent;
    } while (bytes_sent < packet_size);
}

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "Required arguments: [SERVER_IP], [SERVER_PORT]\n";
        return EXIT_FAILURE;
    }

    const char* server_ip = argv[1];
    int server_port = std::stoi(argv[2]);

    sockaddr_in sockaddr;
    int fd1 = socket(AF_INET, SOCK_STREAM, 0);
    if (fd1 < 0) {
        std::cerr << "socket() failed. " << strerror(errno) << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "socket1 created\n";
    int fd2 = socket(AF_INET, SOCK_STREAM, 0);
    if (fd2 < 0) {
        std::cerr << "socket() failed. " << strerror(errno) << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "socket2 created\n";

    std::memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sin_family = AF_INET;
    inet_aton(server_ip, &sockaddr.sin_addr);
    sockaddr.sin_port = htons(server_port);

    if (connect(fd1, reinterpret_cast<struct sockaddr*>(&sockaddr), sizeof(sockaddr))) {
        std::cerr << "connect() failed. " << strerror(errno);
        return EXIT_FAILURE;
    }
    std::cout << "connected to " << server_ip << ':' << server_port << '\n';
    if (connect(fd2, reinterpret_cast<struct sockaddr*>(&sockaddr), sizeof(sockaddr))) {
        std::cerr << "connect() failed. " << strerror(errno);
        return EXIT_FAILURE;
    }
    std::cout << "connected to " << server_ip << ':' << server_port << '\n';

    int one = 1;
    if (setsockopt(fd1, SOL_TCP, TCP_NODELAY, &one, sizeof(one))) {
        std::cerr << "setsockopt() error. " << strerror(errno) << '\n';
        return EXIT_FAILURE;
    }
    if (setsockopt(fd2, SOL_TCP, TCP_NODELAY, &one, sizeof(one))) {
        std::cerr << "setsockopt() error. " << strerror(errno) << '\n';
        return EXIT_FAILURE;
    }

    uint8_t packet;
    const size_t packet_size = sizeof(packet);

    // TCP Warm Up
    int count = 100000;
    while (count--) {
        send_packet(fd1, reinterpret_cast<char*>(&packet), packet_size);
    }

    count = 100000;
    const int sleep_time = 1;
    std::vector<int64_t> send_latency(count);
    int packets_sent = 0;
    while (count--) {
        auto start = std::chrono::steady_clock::now();
        send_packet(fd1, reinterpret_cast<char*>(&packet), packet_size);
        auto end = std::chrono::steady_clock::now();
        send_latency[packets_sent] = end.time_since_epoch().count() - start.time_since_epoch().count();
        busy_wait_for(std::chrono::milliseconds(sleep_time));
        send(fd2, &packet, packet_size, 0);
        busy_wait_for(std::chrono::milliseconds(sleep_time));
        ++packets_sent;
    }

    close(fd1);
    close(fd2);
    dump_csv(send_latency, 1, "two_clients");
}