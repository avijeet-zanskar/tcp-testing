//
// Created by avijeet on 18/3/24.
//

#include "asio_tcp_client.h"

#include "packet.hpp"
#include "util.hpp"

#include <thread>
#include <iostream>

int main(int argc, char** argv) {
    if (argc != 6) {
        std::cerr << "Required arguments: [LOCAL IP], [LOCAL PORT], [SERVER IP], [SERVER PORT], [CLIENT_NUM]\n";
        return EXIT_FAILURE;
    }

    const char* local_ip = argv[1];
    int local_port = std::stoi(argv[2]);
    const char* server_ip = argv[3];
    int server_port = std::stoi(argv[4]);
    int client_num = std::stoi(argv[5]);

    constexpr uint64_t count = 10000;
    uint64_t reps = count;
    uint64_t bytes_read = 0;
    std::vector<int64_t> sends(count);
    std::vector<int64_t> acks(count);

    boost::asio::io_context ioc{BOOST_ASIO_CONCURRENCY_HINT_UNSAFE};
    asio_tcp_client_manager tcp_client_manager(ioc);
    auto on_read = [&ioc, &acks, &bytes_read, count](tcp_socket* sock, unsigned char* buf, int32_t len){
        std::memcpy((char*)acks.data() + bytes_read, buf, len);
        bytes_read += len;
        //std::cout << "read " << len << " bytes\n";
        if (bytes_read == sizeof(int64_t) * count) {
            ioc.stop();
        }
    };
    auto on_connect = [&reps, &sends, count](tcp_socket* sock, const std::string& host, uint16_t port) {
        packet256 packet{};
        size_t packet_size = sizeof(packet);
        while (reps) {
            sends[count - reps] = std::chrono::system_clock::now().time_since_epoch().count();
            sock->send(reinterpret_cast<char*>(&packet), packet_size);
            --reps;
        }
    };

    tcp_client_manager.async_connect(local_ip, local_port, server_ip, server_port, on_read, on_connect, false);
    ioc.run();
    std::vector<int64_t> diff;
    for (int i = 0; i < count; ++i) {
        diff.push_back(acks[i] - sends[i]);
    }
    dump_csv(diff, client_num, "asio_async");
    print_stats(diff);
}