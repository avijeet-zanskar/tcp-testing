cmake_minimum_required(VERSION 3.27)
project(etr_server)
project(etr_server_ex)
project(etr_client)
project(etr_client_ex)
project(one_client)
project(two_clients)
project(connection_limit)
project(asio_client)
project(asio_client_async)

set(CMAKE_CXX_STANDARD 20)

add_compile_options(-march=x86-64-v3 -mtune=raptorlake)

add_executable(etr_server server.cpp)
target_link_libraries(etr_server exanic exasock_ext)
add_executable(etr_server_ex etr_server_ex.cpp)

add_executable(etr_client client.cpp)
target_link_libraries(etr_client exanic exasock_ext)

add_executable(etr_client_ex etr_client_ex.cpp)
target_link_libraries(etr_client_ex exanic exasock_ext)

add_executable(one_client one_client.cpp)
add_executable(two_clients two_clients.cpp)

add_executable(connection_limit connection_limit.cpp)
target_link_libraries(connection_limit exanic exasock_ext)

add_executable(asio_client_async asio_client_async.cpp asio_tcp_client.cpp tcp_socket.cpp)
target_link_libraries(asio_client_async ssl crypto exanic exasock_ext)

add_executable(asio_client asio_client.cpp asio_tcp_client.cpp tcp_socket.cpp)
target_link_libraries(asio_client ssl crypto exanic exasock_ext)
