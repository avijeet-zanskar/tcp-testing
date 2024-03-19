#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <csignal>
#include <cstring>
#include <iostream>
#include <memory>
#include <map>
#include <vector>

#include "packet.hpp"
#include "util.hpp"

struct Frame {
    ether_header eh;
    iphdr ih;
    tcphdr uh;
} __attribute((packed));

volatile bool exit_flag = false;

void handle_interrupt(int) {
    exit_flag = true;
}

int64_t ack_timestamp;

constexpr int MAX_EPOLL_EVENTS = 10;

int main(int argc, char** argv) {
    signal(SIGTERM, handle_interrupt);
    signal(SIGINT, handle_interrupt);
    const char* server_ip;
    int server_port = 0;
    if (argc == 2) {
        std::cerr << "No port provided.\n";
        server_ip = argv[1];
    } else if (argc == 3) {
        server_ip = argv[1];
        server_port = std::stoi(argv[2]);
    } else {
        std::cerr << "Required arguments: [SERVER IP], [SERVER PORT]\n";
        return EXIT_FAILURE;
    }

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        std::cerr << "socket() error. " << strerror(errno) << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "socket created\n";

    int one = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))) {
        std::cerr << "setsockopt() error. " << strerror(errno) << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "socket options set\n";

    sockaddr_in sock_addr;
    socklen_t sock_len = sizeof(sock_addr);
    std::memset(&sock_addr, 0, sock_len);
    std::memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;
    inet_aton(server_ip, &sock_addr.sin_addr);
    sock_addr.sin_port = htons(server_port);

    if (bind(listen_fd, reinterpret_cast<sockaddr*>(&sock_addr), sizeof(sock_addr))) {
        std::cerr << "bind() error. " << strerror(errno) << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "bound successfully\n";
    if (server_port == 0) {
        if (getsockname(listen_fd, reinterpret_cast<sockaddr*>(&sock_addr), &sock_len) < 0) {
            std::cerr << "getsockname() error. " << strerror(errno) << '\n';
            return EXIT_FAILURE;
        }
        server_port = ntohs(sock_addr.sin_port);
        std::cerr << "Using port " << server_port << ".\n";
    }

    if (listen(listen_fd, 10)) {
        std::cerr << "listen() error. " << strerror(errno) << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "listening at port " << server_port << '\n';

    int epoll_fd = epoll_create(10);
    if (epoll_fd < 0) {
        std::cerr << "epoll_create() error. " << strerror(errno) << '\n';
        return EXIT_FAILURE;
    }
    epoll_event event, events[MAX_EPOLL_EVENTS];
    event.events = EPOLLIN;
    event.data.fd = listen_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &event) < 0) {
        std::cerr << "epoll_ctl() error. " << strerror(errno) << '\n';
        return EXIT_FAILURE;
    }
    packet256 packet;
    int packet_size = sizeof(packet);
    std::map<int, int> clients;
    uint64_t timeout = 0;
    do {
        ++timeout;
        if (int ready_fd = epoll_wait(epoll_fd, events, MAX_EPOLL_EVENTS, -1); ready_fd > 0) {
            timeout = 0;
            for (int i = 0; i < ready_fd; ++i) {
                if (events[i].data.fd == listen_fd and (events[i].events & EPOLLIN)) {
                    std::memset(&sock_addr, 0, sock_len);
                    int client_fd = accept(listen_fd, reinterpret_cast<sockaddr*>(&sock_addr), &sock_len);
                    if (client_fd < 0) {
                        std::cerr << "accept() error. " << strerror(errno) << '\n';
                        return EXIT_FAILURE;
                    }
                    std::cout << "accepted connection request from " << client_fd << '\n';
                    event.events = EPOLLIN | EPOLLRDHUP | EPOLLHUP;
                    event.data.fd = client_fd;
                    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &event) < 0) {
                        std::cerr << "epoll_ctl() error. " << strerror(errno) << '\n';
                        return EXIT_FAILURE;
                    }
                } else {
                    int received_size = 0;
                    ack_timestamp = std::chrono::system_clock::now().time_since_epoch().count();
                    while (received_size != packet_size) {
                        ssize_t size = recv(events[i].data.fd, reinterpret_cast<char*>(&packet) + received_size, sizeof(packet) - received_size, 0); // try MSG_WAITALL
                        if (size == 0 and events[i].events & EPOLLRDHUP) {
                            std::cout << "connection to fd " << events[i].data.fd << " closed\n";
                            std::cout << "discarding " << received_size << " bytes\n";
                            if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, &events[i]) < 0) {
                                std::cerr << "epoll_ctl() failed. " << strerror(errno) << '\n';
                                return EXIT_FAILURE;
                            }
                            break;
                        }
                        received_size += size;
                    }
                    size_t bytes_sent = send_packet(events[i].data.fd, reinterpret_cast<char*>(&ack_timestamp), sizeof(ack_timestamp));
                    //std::cout << std::chrono::system_clock::now().time_since_epoch().count() - packet.data[0] << '\n';
                    clients[events[i].data.fd]++;
                }
            }
        }
    } while (!exit_flag and timeout < 1000000000);

    for (const auto [client, packets] : clients) {
        std::cout << "Received " << packets - 1 << " packets from fd " << client << '\n';
        close(client);
    }
    close(epoll_fd);
    close(listen_fd);
}