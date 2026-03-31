#pragma once

#include "common/tls_context.h"
#include <string>
#include <vector>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>

namespace smartgrid {

// Framed message protocol: [4-byte length][payload]
class NetworkUtils {
public:
    // Send a length-prefixed message over SSL
    static bool send_message(SSL* ssl, const std::string& data);
    static bool send_message(SSL* ssl, const void* data, size_t len);

    // Receive a length-prefixed message over SSL
    static std::string recv_message(SSL* ssl);

    // Simple protocol: type byte + payload
    static bool send_typed(SSL* ssl, uint8_t type, const std::string& data);
    static bool recv_typed(SSL* ssl, uint8_t& type, std::string& data);
};

// Message types
enum class MsgType : uint8_t {
    KEY_REQUEST = 0x01,
    KEY_PARAMS = 0x02,
    KEY_PUBLIC = 0x03,
    KEY_RELIN = 0x04,
    KEY_DONE = 0x05,
    METER_DATA = 0x10,
    AGGREGATED_DATA = 0x20,
    ANALYTICS_REQUEST = 0x30,
    ANALYTICS_RESPONSE = 0x31,
    ACK = 0xFE,
    ERROR_MSG = 0xFF
};

// TLS TCP Server
class TLSServer {
public:
    using ClientHandler = std::function<void(SSL* ssl, int fd)>;

    TLSServer(TLSContext& tls_ctx, int port, ClientHandler handler);
    ~TLSServer();

    void start();
    void stop();
    bool is_running() const { return running_; }

private:
    TLSContext& tls_ctx_;
    int port_;
    int server_fd_ = -1;
    ClientHandler handler_;
    std::atomic<bool> running_{false};
    std::thread accept_thread_;
    std::vector<std::thread> client_threads_;
    std::mutex threads_mtx_;

    void accept_loop();
};

// TLS TCP Client
class TLSClient {
public:
    TLSClient(TLSContext& tls_ctx);
    ~TLSClient();

    bool connect(const std::string& host, int port, int timeout_ms = 5000);
    bool connect_with_retry(const std::string& host, int port,
                            int attempts = 3, int delay_ms = 1000, int timeout_ms = 5000);
    void disconnect();

    SSL* ssl() const { return ssl_; }
    bool is_connected() const { return connected_; }

private:
    TLSContext& tls_ctx_;
    SSL* ssl_ = nullptr;
    int fd_ = -1;
    bool connected_ = false;
};

} // namespace smartgrid
