/**
 * Created by vibhanshu on 2023-12-29
 * Edited by mukul on 2024-02-19
 */

#include "asio_tcp_client.h"

tcp_socket* asio_tcp_client_manager::connect(const std::string& local_ip,
                                             uint16_t local_port,
                                             const std::string& remote_ip,
                                             uint16_t remote_port,
                                             cb_on_read&& cb,
                                             bool tls_connect) {
    if (tls_connect) {
        std::cout << "[AsioTCPClientManager] Initiating TLS connection";
        tcp_socket* sock = new asio_tcp_tls_socket(m_ioc, m_ctx, std::move(cb), m_keep_alive, m_reuse_addr);
        if (sock->connect(local_ip, local_port, remote_ip, remote_port)) {
            return sock;
        } else {
            return nullptr;
        }
    } else {
        std::cout << "[AsioTCPClientManager] Initiating simple TCP connection";
        tcp_socket* sock = new asio_tcp_socket(m_ioc, std::move(cb), m_keep_alive, m_reuse_addr);
        if (sock->connect(local_ip, local_port, remote_ip, remote_port)) {
            return sock;
        } else {
            return nullptr;
        }
    }
}

bool asio_tcp_client_manager::async_connect(const std::string& local_ip,
                                            uint16_t local_port,
                                            const std::string& remote_ip,
                                            uint16_t remote_port,
                                            cb_on_read&& read_cb,
                                            cb_on_connect&& connect_cb,
                                            bool tls_connect) {
    if (tls_connect) {
        std::cout << "[AsioTCPClientManager] Initiating TLS connection";
        tcp_socket* sock = new asio_tcp_tls_socket(m_ioc, m_ctx, std::move(read_cb), m_keep_alive, m_reuse_addr);
        return sock->async_connect(local_ip, local_port, remote_ip, remote_port, std::move(connect_cb));
    } else {
        std::cout << "[AsioTCPClientManager] Initiating simple TCP connection";
        tcp_socket* sock = new asio_tcp_socket(m_ioc, std::move(read_cb), m_keep_alive, m_reuse_addr);
        return sock->async_connect(local_ip, local_port, remote_ip, remote_port, std::move(connect_cb));
    }
}

bool asio_tcp_client_manager::close(tcp_socket* asio_sock) {
    std::cout << "[AsioTCPClientManager] Closing socket";
    return asio_sock->close();
}
