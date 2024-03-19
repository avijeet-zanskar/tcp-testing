/**
 * Created by srijan on 2023-10-27
 * Edited by mukul on 2024-02-19
 */

#ifndef ZR_ADAPTER_ASIO_TCP_CLIENT_H
#define ZR_ADAPTER_ASIO_TCP_CLIENT_H

#include "tcp_socket.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#include <boost/asio.hpp>
#pragma GCC diagnostic pop

// ZR_ADAPTER_NS_BEGIN

class asio_tcp_client_manager {
  public:
    using cb_on_connect = tcp_socket::cb_on_connect;
    using cb_on_read = tcp_socket::cb_on_read;

    asio_tcp_client_manager(boost::asio::io_context& ioc) : m_ioc{ioc} {
    }

    tcp_socket* connect(const std::string& local_ip,
                        uint16_t local_port,
                        const std::string& remote_ip,
                        uint16_t remote_port,
                        cb_on_read&& cb,
                        bool tls_connect);
    bool async_connect(const std::string& local_ip,
                       uint16_t local_port,
                       const std::string& remote_ip,
                       uint16_t remote_port,
                       cb_on_read&& read_cb,
                       cb_on_connect&& connect_cb,
                       bool tls_connect);
    int32_t send(tcp_socket* asio_socket, const char* buf, int32_t len) {
        return asio_socket->send(buf, len);
    }
    bool close(tcp_socket* asio_sock);

  private:
    static constexpr bool m_reuse_addr = true;
    static constexpr bool m_keep_alive = true;
    boost::asio::io_context& m_ioc;
    boost::asio::ssl::context m_ctx{boost::asio::ssl::context::tlsv13_client};
};

// ZR_ADAPTER_NS_END

#endif
