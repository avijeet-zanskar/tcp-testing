#include "tcp_socket.h"
#include "boost/asio/ssl/verify_mode.hpp"

asio_tcp_socket::asio_tcp_socket(boost::asio::io_context& ioc, cb_on_read&& cb, bool keep_alive, bool reuse_addr)
    : m_sock(ioc), m_keep_alive{keep_alive}, m_reuse_addr{reuse_addr}, on_read_cb{std::move(cb)} {
}

bool asio_tcp_socket::connect(const std::string& local_ip,
                              uint16_t local_port,
                              const std::string& remote_ip,
                              uint16_t remote_port) {
    boost::system::error_code ec;
    boost::asio::ip::tcp::endpoint local_endpoint(boost::asio::ip::address::from_string(local_ip.c_str()), local_port);
    boost::asio::ip::tcp::endpoint remote_endpoint(boost::asio::ip::address::from_string(remote_ip.c_str()),
                                                   remote_port);
    boost::asio::socket_base::reuse_address reuse_addr(m_reuse_addr);
    m_sock.open(boost::asio::ip::tcp::v4(), ec);
    if (ec) {
        return on_error(std::format("{}{}{}{}{}{}", "[AsioTCPSocket] Error in opening the socket", ", {", ec.value(), ", ", ec.message(), "}"));
    }
    m_sock.set_option(reuse_addr, ec);
    if (ec) {
        return on_error(std::format("{}{}{}{}{}", "[AsioTCPSocket] asio option SO_REUSEADDR failed (", ec.value(), ", ", ec.message().c_str(), ")"));
    }
    m_sock.bind(local_endpoint, ec);
    if (ec) {
        return on_error(std::format("{}{}{}{}{}{}{}{}{}", "[AsioTCPSocket] Error binding to: ", local_ip, ":", local_port, ", {", ec.value(), ", ", ec.message(), "}"));
    }
    m_sock.connect(remote_endpoint, ec);
    if (ec) {
        return on_error(std::format("{}{}{}{}{}{}{}{}{}", "[AsioTCPSocket] Error connecting to: ", local_ip, ":", local_port, ", {", ec.value(), ", ", ec.message(), "}"));
    }
    std::cout << "[AsioTCPSocket] Socket connected successfully\n";
    if (!set_socket_options()) {
        return on_error("[AsioTCPSocket] Unable to set socket options");
    }
    start_receiving();
    return true;
}

bool asio_tcp_socket::async_connect(const std::string& local_ip,
                                    uint16_t local_port,
                                    const std::string& remote_ip,
                                    uint16_t remote_port,
                                    cb_on_connect&& connect_cb) {
    boost::system::error_code ec;
    boost::asio::ip::tcp::endpoint local_endpoint(boost::asio::ip::address::from_string(local_ip.c_str()), local_port);
    boost::asio::ip::tcp::endpoint remote_endpoint(boost::asio::ip::address::from_string(remote_ip.c_str()),
                                                   remote_port);
    boost::asio::socket_base::reuse_address reuse_addr(m_reuse_addr);
    m_sock.open(boost::asio::ip::tcp::v4(), ec);
    if (ec) {
        return on_error(std::format("{}{}{}{}{}{}", "[AsioTCPSocket] Error in opening the socket", ", {", ec.value(), ", ", ec.message(), "}"));
    }
    m_sock.set_option(reuse_addr, ec);
    if (ec) {
        return on_error(std::format("{}{}{}{}{}", "[AsioTCPSocket] asio option SO_REUSEADDR failed (", ec.value(), ", ", ec.message().c_str(), ")"));
    }
    m_sock.bind(local_endpoint, ec);
    if (ec) {
        return on_error(std::format("{}{}{}{}{}{}{}{}{}", "[AsioTCPSocket] Error connecting to: ", local_ip, ":", local_port, ", {", ec.value(), ", ", ec.message(), "}"));
    }
    m_sock.async_connect(
        remote_endpoint,
        [this, remote_ip, remote_port, cb = std::move(connect_cb)](const boost::system::error_code& ec) {
            std::cout << "Connected through: " << m_sock.local_endpoint().address().to_string() << ":"
                    << m_sock.local_endpoint().port() << '\n';
            handle_connect(ec, remote_ip, remote_port, cb);
        });
    return true;
}

bool asio_tcp_socket::close() {
    boost::system::error_code ec;
    m_sock.cancel();
    m_sock.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    if (ec) {
        std::cerr << "[AsioTCPSocket] Shutdown socket (" << ec.value() << ", " << ec.message().c_str() << ")";
        return false;
    }
    m_sock.close(ec);
    if (ec) {
        std::cerr << "[AsioTCPSocket] Close socket (" << ec.value() << ", " << ec.message().c_str() << ")";
        return false;
    }
    return true;
}

bool asio_tcp_socket::set_socket_options() {
    boost::system::error_code ec;
    auto get_msg = [&ec](const char* error_type) {
        std::string msg = std::format("{}{}{}{}{}{}{}", "[AsioTCPSocket] asio option ", error_type, " failed (", ec.value(), ", ", ec.message().c_str(), ")");
        return msg;
    };
    m_sock.non_blocking(true);
    boost::asio::ip::tcp::no_delay option(true);
    m_sock.set_option(option, ec);
    if (ec) {
        return on_error(get_msg("TCP_NODELAY"));
    }
    boost::asio::detail::socket_option::integer<SOL_TCP, TCP_KEEPIDLE> ka_idle_time(2);
    m_sock.set_option(ka_idle_time, ec);
    if (ec) {
        return on_error(get_msg("TCP_KEEPIDLE"));
    }
    boost::asio::detail::socket_option::integer<SOL_TCP, TCP_KEEPINTVL> ka_interval(1);
    m_sock.set_option(ka_interval, ec);
    if (ec) {
        return on_error(get_msg("TCP_KEEPINTVL"));
    }
    boost::asio::detail::socket_option::integer<SOL_TCP, TCP_KEEPCNT> ka_probes(3);
    m_sock.set_option(ka_probes, ec);
    if (ec) {
        return on_error(get_msg("TCP_KEEPCNT"));
    }
    boost::asio::socket_base::keep_alive keep_alive(m_keep_alive);
    m_sock.set_option(keep_alive, ec);
    if (ec) {
        return on_error(get_msg("SO_KEEPALIVE"));
    }
    std::cout << "[AsioTCPSocket] All Socket Options Set";
    return true;
}

void asio_tcp_socket::handle_connect(const boost::system::error_code& ec,
                                     const std::string& host,
                                     uint16_t port,
                                     cb_on_connect cb) {
    if (ec) {
        std::cerr << "[AsioTCPSocket] Error connecting to: " << host << ":" << port << ", {" << ec.value() << ", "
                 << ec.message() << "}";
        return cb(nullptr, host, port);
    }

    if (!set_socket_options()) {
        std::cerr << "[AsioTCPSocket] Unable to set socket options";
        return cb(nullptr, host, port);
    }
    cb(this, host, port);
    start_receiving();
}

void asio_tcp_socket::start_receiving() {
    if (is_open()) {
        m_sock.async_receive(boost::asio::null_buffers(), [this](const boost::system::error_code& ec, std::size_t) {
            if (!ec) [[likely]] {
                boost::system::error_code err;
                int br = 0;
                do {
                    br = int(m_sock.receive(boost::asio::buffer(m_buffer, m_recv_buf_size), 0, err));
                    std::cout << "[AsioTCPSocket] Bytes read: " << br;
                    if (err) [[unlikely]] {
                        std::cerr << "[AsioTCPSocket] Error while receiving";
                        if (err != boost::asio::error::would_block) [[unlikely]] {
                            std::cerr << "[AsioTCPSocket] Error other than blocking";
                            if (err != boost::asio::error::eof) {
                                std::cerr << "[AsioTCPSocket] (" << ec.value() << ", " << ec.message().c_str() << ")";
                            }
                            if (is_open()) [[likely]] {
                                on_read_cb(this, nullptr, -1);
                                close();
                            }
                            return;
                        }
                        std::cerr << "[AsioTCPSocket] Error. Breaking";
                        break; // EAGAIN
                    }
                    if (br <= 0) [[unlikely]] {
                        std::cerr << "[AsioTCPSocket] Read 0 or less bytes, receive error: (" << err.value() << ", "
                                 << err.message().c_str() << ")";
                        if (is_open()) [[likely]] {
                            std::cerr << "[AsioTCPSocket] Closing socket";
                            on_read_cb(this, nullptr, br);
                            close();
                        }
                        return;
                    }
                    if (is_open()) [[likely]] {
                        on_read_cb(this, m_buffer, br);
                    }
                } while (br == int(m_recv_buf_size));
            } else {
                std::cerr << "[AsioTCPSocket] Error while receiving message";
                if (is_open()) {
                    std::cerr << "[AsioTCPSocket] (" << ec.value() << ", " << ec.message().c_str() << ")";
                    on_read_cb(this, nullptr, -1);
                    close();
                }
                return;
            }
            start_receiving();
        });
    }
}

asio_tcp_tls_socket::asio_tcp_tls_socket(boost::asio::io_context& ioc,
                                         boost::asio::ssl::context& ctx,
                                         cb_on_read&& cb,
                                         bool keep_alive,
                                         bool reuse_addr,
                                         std::string cert_file)
    : m_sock(ioc, ctx),
      m_ctx(ctx),
      m_keep_alive{keep_alive},
      m_reuse_addr{reuse_addr},
      m_verify_cert{cert_file.length() != 0},
      on_read_cb{std::move(cb)},
      m_cert_file{cert_file} {
}

bool asio_tcp_tls_socket::connect(const std::string& local_ip,
                                  uint16_t local_port,
                                  const std::string& remote_ip,
                                  uint16_t remote_port) {
    boost::system::error_code ec;
    boost::asio::ip::tcp::endpoint local_endpoint(boost::asio::ip::address::from_string(local_ip.c_str()), local_port);
    boost::asio::ip::tcp::endpoint remote_endpoint(boost::asio::ip::address::from_string(remote_ip.c_str()),
                                                   remote_port);
    boost::asio::socket_base::reuse_address reuse_addr(m_reuse_addr);
    m_sock.lowest_layer().open(boost::asio::ip::tcp::v4(), ec);
    if (ec) {
        return on_error(std::format("{}{}{}{}{}", "[AsioTLSSocket] Error in opening the socket", ", (", ec.value(), ", ", ec.message(), ")"));
    }
    m_sock.lowest_layer().set_option(reuse_addr, ec);
    if (ec) {
        return on_error(std::format("{}{}{}{}{}", "[AsioTLSSocket] asio option SO_REUSEADDR failed (", ec.value(), ", ", ec.message().c_str(), ")"));
    }
    m_sock.lowest_layer().bind(local_endpoint, ec);
    if (ec) {
        return on_error(std::format("{}{}{}{}{}{}{}{}{}", "[AsioTLSSocket] Error binding to: ", local_ip, ":", local_port, ", (", ec.value(), ", ", ec.message(), ")"));
    }
    m_sock.lowest_layer().connect(remote_endpoint, ec);
    if (ec) {
        return on_error(std::format("", "[AsioTLSSocket] Error connecting to: ", local_ip, ":", local_port, ", (", ec.value(), ", ", ec.message(), ")"));
    }
    std::cout << "[AsioTLSSocket] Socket connected successfully";
    if (!set_socket_options()) {
        return on_error("[AsioTLSSocket] Unable to set socket options");
    }
    if (!tls_handshake()) {
        return on_error("[AsioTLSSocket] Unable to perform TLS handshake");
    }
    start_receiving();
    return true;
}

bool asio_tcp_tls_socket::async_connect(const std::string& local_ip,
                                        uint16_t local_port,
                                        const std::string& host,
                                        uint16_t port,
                                        cb_on_connect&& connect_cb) {
    boost::system::error_code ec;
    boost::asio::ip::tcp::endpoint local_endpoint(boost::asio::ip::address::from_string(local_ip.c_str()), local_port);
    boost::asio::ip::tcp::endpoint host_endpoint(boost::asio::ip::address::from_string(host.c_str()), port);
    boost::asio::socket_base::reuse_address reuse_addr(m_reuse_addr);
    m_sock.lowest_layer().open(boost::asio::ip::tcp::v4(), ec);
    if (ec) {
        return on_error(std::format("{}{}{}{}{}", "[AsioTLSSocket] Error in opening the socket", ", (", ec.value(), ", ", ec.message(), ")"));
    }
    m_sock.lowest_layer().set_option(reuse_addr, ec);
    if (ec) {
        return on_error(std::format("{}{}{}{}{}", "[AsioTLSSocket] asio option SO_REUSEADDR failed (", ec.value(), ", ", ec.message().c_str(), ")"));
    }
    m_sock.lowest_layer().bind(local_endpoint, ec);
    if (ec) {
        return on_error(std::format("{}{}{}{}{}{}{}{}{}", "[AsioTLSSocket] Error binding to: ", local_ip, ":", local_port, ", (", ec.value(), ", ", ec.message(), ")"));
    }
    m_sock.lowest_layer().async_connect(
        host_endpoint,
        [this, host, port, cb = std::move(connect_cb)](const boost::system::error_code& ec) {
            std::cout << "Connected through: " << m_sock.lowest_layer().local_endpoint().address().to_string() << ":"
                    << m_sock.lowest_layer().local_endpoint().port();
            handle_connect(ec, host, port, cb);
        });
    return true;
}

bool asio_tcp_tls_socket::close() {
    boost::system::error_code ec;
    if (m_is_handshaked) {
        m_sock.lowest_layer().non_blocking(false);
        m_sock.shutdown(ec);
        if (ec) [[unlikely]] {
            std::cerr << "[AsioTLSSocket] Shutdown SSL (" << ec.value() << ", " << ec.message().c_str() << ")";
        }
    }
    m_sock.lowest_layer().cancel();
    m_sock.lowest_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    if (ec) {
        std::cerr << "[AsioTLSSocket] Shutdown socket (" << ec.value() << ", " << ec.message().c_str() << ")";
        return false;
    }
    m_sock.lowest_layer().close(ec);
    if (ec) {
        std::cerr << "[AsioTLSSocket] Close socket (" << ec.value() << ", " << ec.message().c_str() << ")";
        return false;
    }
    return true;
}

bool asio_tcp_tls_socket::set_socket_options() {
    boost::system::error_code ec;
    auto get_msg = [&ec](const char* error_type) {
        std::string msg = std::format("{}{}{}{}{}{}{}", "[AsioTCPSocket] asio option ", error_type, " failed (", ec.value(), ", ", ec.message().c_str(), ")");
        return msg;
    };
    m_sock.lowest_layer().non_blocking(true);
    boost::asio::ip::tcp::no_delay option(true);
    m_sock.lowest_layer().set_option(option, ec);
    if (ec) {
        return on_error(get_msg("TCP_NODELAY"));
    }
    boost::asio::detail::socket_option::integer<SOL_TCP, TCP_KEEPIDLE> ka_idle_time(2);
    m_sock.lowest_layer().set_option(ka_idle_time, ec);
    if (ec) {
        return on_error(get_msg("TCP_KEEPIDLE"));
    }
    boost::asio::detail::socket_option::integer<SOL_TCP, TCP_KEEPINTVL> ka_interval(1);
    m_sock.lowest_layer().set_option(ka_interval, ec);
    if (ec) {
        return on_error(get_msg("TCP_KEEPINTVL"));
    }
    boost::asio::detail::socket_option::integer<SOL_TCP, TCP_KEEPCNT> ka_probes(3);
    m_sock.lowest_layer().set_option(ka_probes, ec);
    if (ec) {
        return on_error(get_msg("TCP_KEEPCNT"));
    }
    boost::asio::socket_base::keep_alive keep_alive(m_keep_alive);
    m_sock.lowest_layer().set_option(keep_alive, ec);
    if (ec) {
        return on_error(get_msg("SO_KEEPALIVE"));
    }
    std::cout << "[AsioTLSSocket] All Socket Options Set";
    return true;
}

void asio_tcp_tls_socket::handle_connect(const boost::system::error_code& ec,
                                         const std::string& host,
                                         uint16_t port,
                                         cb_on_connect cb) {
    using boost::asio::ip::tcp;
    using boost::asio::ssl::stream;
    if (ec) {
        std::cerr << "[AsioTLSSocket] Error connecting to: " << host << ":" << port << ", {" << ec.value() << ", "
                 << ec.message() << "}";
        return cb(nullptr, host, port);
    }

    if (!set_socket_options()) {
        std::cerr << "[AsioTLSSocket] Unable to set socket options";
        return cb(nullptr, host, port);
    }
    boost::system::error_code err_c;
    boost::asio::ssl::verify_mode mode{boost::asio::ssl::verify_none};
    if (m_verify_cert) {
        mode = boost::asio::ssl::verify_fail_if_no_peer_cert | boost::asio::ssl::verify_peer;
    }
    m_ctx.set_verify_mode(mode, err_c);
    if (ec) {
        on_error("[AsioTLSSocket] Unable to set TLS verify mode");
        return cb(nullptr, host, port);
    }
    if (m_verify_cert) {
        m_ctx.load_verify_file(m_cert_file, err_c);
        if (ec) {
            on_error("[AsioTLSSocket] Unable to set load TLS verify certificate file");
            return cb(nullptr, host, port);
        }
    }
    stream<tcp::socket>::handshake_type hs_type = stream<tcp::socket>::handshake_type::client;
    m_sock.async_handshake(hs_type, [this, host, port, cb = std::move(cb)](const boost::system::error_code& ec) {
        handle_tls_handshake(ec, host, port, cb);
    });
}

void asio_tcp_tls_socket::handle_tls_handshake(const boost::system::error_code& ec,
                                               const std::string& host,
                                               uint16_t port,
                                               cb_on_connect cb) {
    if (ec) {
        on_error(std::format("{}{}{}{}{}{}", "[AsioTLSSocket] Handshake failed", ", (", ec.value(), ", ", ec.message(), ")"));
        return cb(nullptr, host, port);
    }
    m_is_handshaked = true;
    cb(this, host, port);
    start_receiving();
}

bool asio_tcp_tls_socket::tls_handshake() {
    boost::system::error_code ec;
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket>::handshake_type hs_type
        = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>::handshake_type::client;
    m_sock.handshake(hs_type, ec);
    if (ec) {
        std::cerr << "[AsioTLSSocket] Handshake failed"
                 << ", {" << ec.value() << ", " << ec.message() << "}";
        close();
        return false;
    }
    return true;
}

void asio_tcp_tls_socket::start_receiving() {
    if (is_open() && m_is_handshaked) {
        m_sock.async_read_some(boost::asio::buffer(m_buffer, m_recv_buf_size),
                               [this](const boost::system::error_code& ec, std::size_t sz) {
                                   if (!ec) [[likely]] {
                                       std::cout << "[AsioTCPClientManager] Bytes read: " << sz;
                                       if (sz <= 0) [[unlikely]] {
                                           std::cerr << "[AsioTCPClientManager] Read 0 or less bytes";
                                           if (is_open()) [[likely]] {
                                               std::cerr << "[AsioTCPClientManager] Closing socket";
                                               on_read_cb(this, nullptr, sz);
                                               close();
                                           }
                                           return;
                                       } else {
                                           on_read_cb(this, m_buffer, sz);
                                       }
                                   } else {
                                       std::cerr << "[AsioTCPClientManager] Error while receiving message";
                                       if (is_open()) {
                                           std::cerr << "[AsioTCPClientManager] (" << ec.value() << ", "
                                                    << ec.message().c_str() << ")";
                                           on_read_cb(this, nullptr, -1);
                                           close();
                                       }
                                       return;
                                   }
                                   start_receiving();
                               });
    }
}