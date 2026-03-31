#include "common/network.h"
#include "common/logger.h"
#include "common/metrics.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cstring>
#include <stdexcept>

namespace smartgrid {

// ==================== NetworkUtils ====================

bool NetworkUtils::send_message(SSL* ssl, const std::string& data) {
    return send_message(ssl, data.data(), data.size());
}

bool NetworkUtils::send_message(SSL* ssl, const void* data, size_t len) {
    // Send 4-byte length header (network byte order)
    uint32_t net_len = htonl(static_cast<uint32_t>(len));
    int ret = SSL_write(ssl, &net_len, 4);
    if (ret <= 0) return false;

    // Send payload
    size_t sent = 0;
    const char* ptr = static_cast<const char*>(data);
    while (sent < len) {
        ret = SSL_write(ssl, ptr + sent, static_cast<int>(len - sent));
        if (ret <= 0) return false;
        sent += static_cast<size_t>(ret);
    }
    return true;
}

std::string NetworkUtils::recv_message(SSL* ssl) {
    // Read 4-byte length header
    uint32_t net_len = 0;
    int ret = SSL_read(ssl, &net_len, 4);
    if (ret <= 0) return "";

    uint32_t len = ntohl(net_len);
    if (len == 0 || len > 100 * 1024 * 1024) { // 100MB safety limit
        return "";
    }

    std::string data(len, '\0');
    size_t received = 0;
    while (received < len) {
        ret = SSL_read(ssl, &data[received], static_cast<int>(len - received));
        if (ret <= 0) return "";
        received += static_cast<size_t>(ret);
    }
    return data;
}

bool NetworkUtils::send_typed(SSL* ssl, uint8_t type, const std::string& data) {
    std::string msg(1, static_cast<char>(type));
    msg += data;
    return send_message(ssl, msg);
}

bool NetworkUtils::recv_typed(SSL* ssl, uint8_t& type, std::string& data) {
    std::string msg = recv_message(ssl);
    if (msg.empty()) return false;
    type = static_cast<uint8_t>(msg[0]);
    data = msg.substr(1);
    return true;
}

// ==================== TLSServer ====================

TLSServer::TLSServer(TLSContext& tls_ctx, int port, ClientHandler handler)
    : tls_ctx_(tls_ctx), port_(port), handler_(std::move(handler)) {}

TLSServer::~TLSServer() {
    stop();
}

void TLSServer::start() {
    server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd_ < 0) {
        throw std::runtime_error("Failed to create server socket");
    }

    int opt = 1;
    setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(static_cast<uint16_t>(port_));

    if (bind(server_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(server_fd_);
        throw std::runtime_error("Failed to bind on port " + std::to_string(port_));
    }

    if (listen(server_fd_, 512) < 0) {
        close(server_fd_);
        throw std::runtime_error("Failed to listen on port " + std::to_string(port_));
    }

    running_ = true;
    accept_thread_ = std::thread(&TLSServer::accept_loop, this);
    LOG_INFO("TLSServer", "Listening on port " + std::to_string(port_));
}

void TLSServer::stop() {
    running_ = false;
    if (server_fd_ >= 0) {
        shutdown(server_fd_, SHUT_RDWR);
        close(server_fd_);
        server_fd_ = -1;
    }
    if (accept_thread_.joinable()) accept_thread_.join();
    {
        std::lock_guard<std::mutex> lock(threads_mtx_);
        for (auto& t : client_threads_) {
            if (t.joinable()) t.join();
        }
        client_threads_.clear();
    }
}

void TLSServer::accept_loop() {
    while (running_) {
        struct pollfd pfd{};
        pfd.fd = server_fd_;
        pfd.events = POLLIN;

        int ret = poll(&pfd, 1, 500); // 500ms timeout for checking running_
        if (ret <= 0) continue;

        sockaddr_in client_addr{};
        socklen_t len = sizeof(client_addr);
        int client_fd = accept(server_fd_, reinterpret_cast<sockaddr*>(&client_addr), &len);
        if (client_fd < 0) continue;

        SSL* ssl = tls_ctx_.create_ssl(client_fd);
        if (!tls_ctx_.handshake(ssl)) {
            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        MetricsCollector::instance().record("network", "tls_handshake", 1.0, "count",
            "client=" + std::string(inet_ntoa(client_addr.sin_addr)));

        std::lock_guard<std::mutex> lock(threads_mtx_);
        client_threads_.emplace_back([this, ssl, client_fd]() {
            handler_(ssl, client_fd);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_fd);
        });
    }
}

// ==================== TLSClient ====================

TLSClient::TLSClient(TLSContext& tls_ctx) : tls_ctx_(tls_ctx) {}

TLSClient::~TLSClient() {
    disconnect();
}

bool TLSClient::connect(const std::string& host, int port, int timeout_ms) {
    ScopedTimer timer("network", "client_connect", host + ":" + std::to_string(port));

    fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (fd_ < 0) return false;

    // Set non-blocking for connect timeout
    int flags = fcntl(fd_, F_GETFL, 0);
    fcntl(fd_, F_SETFL, flags | O_NONBLOCK);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

    int ret = ::connect(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (ret < 0 && errno == EINPROGRESS) {
        struct pollfd pfd{};
        pfd.fd = fd_;
        pfd.events = POLLOUT;
        ret = poll(&pfd, 1, timeout_ms);
        if (ret <= 0) {
            close(fd_);
            fd_ = -1;
            return false;
        }
        int error = 0;
        socklen_t len = sizeof(error);
        getsockopt(fd_, SOL_SOCKET, SO_ERROR, &error, &len);
        if (error != 0) {
            close(fd_);
            fd_ = -1;
            return false;
        }
    } else if (ret < 0) {
        close(fd_);
        fd_ = -1;
        return false;
    }

    // Restore blocking
    fcntl(fd_, F_SETFL, flags);

    ssl_ = tls_ctx_.create_ssl(fd_);
    if (!tls_ctx_.handshake(ssl_)) {
        SSL_free(ssl_);
        ssl_ = nullptr;
        close(fd_);
        fd_ = -1;
        return false;
    }

    connected_ = true;
    return true;
}

bool TLSClient::connect_with_retry(const std::string& host, int port,
                                    int attempts, int delay_ms, int timeout_ms) {
    for (int i = 0; i < attempts; i++) {
        if (connect(host, port, timeout_ms)) return true;
        LOG_WARN("TLSClient", "Connection attempt " + std::to_string(i + 1) + "/" +
                 std::to_string(attempts) + " failed, retrying in " +
                 std::to_string(delay_ms) + "ms");
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
    }
    return false;
}

void TLSClient::disconnect() {
    if (ssl_) {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
        ssl_ = nullptr;
    }
    if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
    }
    connected_ = false;
}

} // namespace smartgrid
