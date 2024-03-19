/**
 * Created by mukul on 2024-02-19
 */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#pragma GCC diagnostic pop
#include <cstdint>
#include <iostream>
#include <format>

class tcp_socket {
  public:
    using cb_on_connect = std::function<void(tcp_socket* sock, const std::string& host, uint16_t port)>;
    using cb_on_read = std::function<void(tcp_socket* sock, unsigned char* buf, int32_t len)>;
    tcp_socket() = default;
    virtual ~tcp_socket() = default;

    virtual bool is_open() const = 0;
    virtual int get_fd() = 0;
    virtual bool connect(const std::string& local_ip, uint16_t local_port, const std::string& host, uint16_t port) = 0;
    virtual bool async_connect(const std::string& local_ip,
                               uint16_t local_port,
                               const std::string& remote_ip,
                               uint16_t remote_port,
                               cb_on_connect&& connect_cb) {
        (void)local_ip;
        (void)local_port;
        (void)remote_ip;
        (void)remote_port;
        (void)connect_cb;
        std::cerr << ("[TCPSocket] async connect isn't supported by this socket\n");
        return false;
    }
    virtual int send(const char* buf, int len) = 0;
    virtual bool close() = 0;

  protected:
    static constexpr uint m_recv_buf_size = 65536; // max size of tcp packet

    virtual bool set_socket_options() = 0;
};

class asio_tcp_socket final : public tcp_socket {
  public:
    explicit asio_tcp_socket(boost::asio::io_context& ioc,
                             cb_on_read&& cb,
                             bool keep_alive = true,
                             bool reuse_addr = true);
    ~asio_tcp_socket() override = default;

    bool is_open() const override {
        return m_sock.is_open();
    }
    int get_fd() override {
        return m_sock.native_handle();
    }
    bool connect(const std::string& local_ip, uint16_t local_port, const std::string& host, uint16_t port) override;
    bool async_connect(const std::string& local_ip,
                       uint16_t local_port,
                       const std::string& host,
                       uint16_t port,
                       cb_on_connect&& connect_cb) override;
    [[gnu::always_inline]] inline int send(const char* buf, int len) override {
        size_t sent = 0;
        size_t ulen = (size_t)len;
        while (sent != ulen) {
            auto rem = ulen - sent;
            boost::system::error_code ec;
            auto rc = boost::asio::write(m_sock, boost::asio::buffer(buf + sent, rem), boost::asio::transfer_all(), ec);
            if (ec && ec != boost::asio::error::would_block) [[unlikely]] {
                on_error(std::format("{}{}{}{}{}", "[AsioTCPSocket] (", ec.value(), ", ", ec.message().c_str(), ")"));
                return -1;
            }
            sent += rc;
        }
        return sent;
    }
    bool close() override;

  private:
    bool set_socket_options() override;
    void handle_connect(const boost::system::error_code& ec, const std::string& host, uint16_t port, cb_on_connect cb);
    void start_receiving();
    bool on_error(std::string msg) {
        std::cerr << msg << '\n';
        close();
        return false;
    }

  private:
    boost::asio::ip::tcp::socket m_sock;
    const bool m_keep_alive;
    const bool m_reuse_addr;
    cb_on_read on_read_cb;
    unsigned char m_buffer[m_recv_buf_size];
};

class asio_tcp_tls_socket final : public tcp_socket {
  public:
    asio_tcp_tls_socket(boost::asio::io_context& ioc,
                        boost::asio::ssl::context& ctx,
                        cb_on_read&& cb,
                        bool keep_alive = true,
                        bool reuse_addr = true,
                        std::string cert_file = "");
    ~asio_tcp_tls_socket() override = default;

    bool is_open() const override {
        return m_sock.lowest_layer().is_open();
    }
    int get_fd() override {
        return m_sock.lowest_layer().native_handle();
    }
    bool connect(const std::string& local_ip,
                 uint16_t local_port,
                 const std::string& remote_ip,
                 uint16_t remote_port) override;
    bool async_connect(const std::string& local_ip,
                       uint16_t local_port,
                       const std::string& host,
                       uint16_t port,
                       cb_on_connect&& connect_cb) override;
    [[gnu::always_inline]] inline int send(const char* buf, int len) override {
        size_t sent = 0;
        size_t ulen = (size_t)len;
        while (sent != ulen) {
            auto rem = ulen - sent;
            boost::system::error_code ec;
            auto rc = boost::asio::write(m_sock, boost::asio::buffer(buf + sent, rem), boost::asio::transfer_all(), ec);
            if (ec && ec != boost::asio::error::would_block) [[unlikely]] {
                on_error(std::format("{}{}{}{}{}", "[AsioTCPSocket] (", ec.value(), ", ", ec.message().c_str(), ")"));
                return -1;
            }
            sent += rc;
        }
        return sent;
    }
    bool close() override;

  private:
    bool set_socket_options() override;
    void handle_connect(const boost::system::error_code& ec, const std::string& host, uint16_t port, cb_on_connect cb);
    void
    handle_tls_handshake(const boost::system::error_code& ec, const std::string& host, uint16_t port, cb_on_connect cb);
    bool tls_handshake();
    void start_receiving();
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket>::native_handle_type get_tls_fd() {
        return m_sock.native_handle();
    }
    bool on_error(std::string msg) {
        std::cerr << msg << '\n';
        close();
        return false;
    }

  private:
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> m_sock;
    boost::asio::ssl::context& m_ctx;
    const bool m_keep_alive;
    const bool m_reuse_addr;
    const bool m_verify_cert;
    bool m_is_handshaked{false};
    cb_on_read on_read_cb;
    unsigned char m_buffer[m_recv_buf_size];
    const std::string m_cert_file;
};