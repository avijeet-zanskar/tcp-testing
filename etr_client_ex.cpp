#include <unistd.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <thread>

#include "packet.hpp"
#include "util.hpp"

constexpr int MAX_EPOLL_EVENTS = 10;

int main(int argc, char** argv) {
    if (argc != 4) {
        std::cerr << "Required arguments: [SERVER IP], [SERVER PORT], [CLIENT_NUM]\n";
        return EXIT_FAILURE;
    }

    const char* server_ip = argv[1];
    int server_port = std::stoi(argv[2]);
    int client_num = std::stoi(argv[3]);

    auto fd_opt = create_connection_to(server_ip, server_port);
    if (!fd_opt.has_value()) {
        return EXIT_FAILURE;
    }
    int fd = fd_opt.value();

    constexpr int four_kb = 4 * 1024;
    constexpr int sixteen_kb = 16 * 1024;
    constexpr int one_twenty_eight_kb = 128 * 1024;
    constexpr int two_fifty_six_kb = 256 * 1024;
    auto [exanic, tx] = reserve_exanic_tx_buffer_for_connection(fd, one_twenty_eight_kb);
    if (exanic == nullptr or tx == nullptr) {
        return EXIT_FAILURE;
    }

    auto rx = acquire_exanic_rx_buffer(exanic, fd);
    if (rx == nullptr) {
        return EXIT_FAILURE;
    }

    packet256 packet{};
    packet.data[0] = 0;
    char frame[1024];
    char rx_buf[4096];
    size_t packet_size = sizeof(packet);
    constexpr uint64_t count = 100000;
    uint64_t reps = count;
    std::vector<uint64_t> time_diff(count, -1);
    size_t bytes_written = 0;
    while (reps) {
        auto start = std::chrono::steady_clock::now().time_since_epoch().count();
        DoNotOptimize(fd);
        int bytes_sent = send_packet_exanic(tx, fd, frame, reinterpret_cast<char*>(&packet), packet_size);
        DoNotOptimize(bytes_sent);
        auto end = std::chrono::steady_clock::now().time_since_epoch().count();
        --reps;
        ssize_t rx_size = exanic_receive_frame(rx, rx_buf, sizeof(rx_buf), nullptr);
        if (rx_size > 0) {
            std::memcpy((char*)time_diff.data() + bytes_written, rx_buf + sizeof(FrameHeader), rx_size - sizeof(FrameHeader));
            bytes_written += rx_size - sizeof(FrameHeader);
        }
        busy_wait_for(std::chrono::microseconds(500));
    }
    exanic_release_tx_buffer(tx);
    exanic_release_handle(exanic);
    if (close(fd)) {
        std::cerr << "close() failed. " << strerror(errno);
        return EXIT_FAILURE;
    }

    std::cout << "Connection closed\n";

    dump_csv(time_diff, client_num, "send_time");
    print_stats(time_diff);
}