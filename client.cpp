#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <thread>

#include "packet.hpp"
#include "util.hpp"

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

    packet256 packet{};
    packet.data[0] = 0;
    size_t packet_size = sizeof(packet);
    constexpr uint64_t count = 100000;
    uint64_t reps = count;
    std::vector<uint64_t> time_diff(count, -1);
    while (reps) {
        auto start = std::chrono::steady_clock::now().time_since_epoch().count();
        DoNotOptimize(fd);
        size_t bytes_sent = send_packet(fd, reinterpret_cast<char*>(&packet), packet_size);
        DoNotOptimize(bytes_sent);
        auto end = std::chrono::steady_clock::now().time_since_epoch().count();
        time_diff[count - reps] = end - start;
        --reps;
        busy_wait_for(std::chrono::microseconds(500));
    }
    if (close(fd)) {
        std::cerr << "close() failed. " << strerror(errno);
        return EXIT_FAILURE;
    }

    std::cout << "Connection closed\n";

    dump_csv(time_diff, client_num, "send_time");
    print_stats(time_diff);
}