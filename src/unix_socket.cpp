#include "cnss/unix_socket.hpp"
#include "cnss/logger.hpp"
#include <cerrno>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>

namespace cnss {

UnixControlSocket::~UnixControlSocket() { close(); }

void UnixControlSocket::close() {
    if (fd_ >= 0) ::close(fd_);
    fd_ = -1;
    have_peer_ = false;
    peer_len_ = 0;
    if (!path_.empty()) ::unlink(path_.c_str());
}

bool UnixControlSocket::listen(const std::string& path) {
    close();
    if (path.size() >= sizeof(sockaddr_un::sun_path)) {
        log(LogLevel::Error, "UNIX socket path too long: %s", path.c_str());
        return false;
    }

    fd_ = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd_ < 0) {
        log(LogLevel::Error, "socket(AF_UNIX): %s", std::strerror(errno));
        return false;
    }
    path_ = path;
    ::unlink(path.c_str());

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);
    if (::bind(fd_, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) < 0) {
        log(LogLevel::Error, "bind %s: %s", path.c_str(), std::strerror(errno));
        close();
        return false;
    }
    return true;
}

bool UnixControlSocket::recv_packet(UserPacket& packet) {
    packet = {};
    std::uint8_t buf[0x400]{};
    sockaddr_un peer{};
    socklen_t peer_len = sizeof(peer);
    const ssize_t n = ::recvfrom(fd_, buf, sizeof(buf), MSG_DONTWAIT,
                                 reinterpret_cast<sockaddr*>(&peer), &peer_len);
    if (n < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) return false;
        log(LogLevel::Error, "recvfrom user socket: %s", std::strerror(errno));
        return false;
    }
    if (n < 12) {
        log(LogLevel::Warn, "Invalid number of bytes (%zd) received on socket", n);
        return false;
    }

    std::uint32_t command = 0;
    std::uint32_t len = 0;
    std::memcpy(&command, buf, sizeof(command));
    std::memcpy(&len, buf + 4, sizeof(len));
    log(LogLevel::Debug, "Receive user message: %u, len %u", command, len);

    // Original code reads a whole 0x400-byte datagram and only validates the
    // semantic length for commands that carry data. Keep command 3 payload-free
    // and preserve command 2's exact 8-byte payload requirement in Daemon.
    if (len > static_cast<std::uint32_t>(n - 8) || len > sizeof(buf) - 8) {
        log(LogLevel::Warn, "Invalid user packet length: cmd=%u len=%u packet=%zd", command, len, n);
        return false;
    }

    packet.command = command;
    packet.wire_length = len;
    packet.payload.assign(buf + 8, buf + 8 + len);
    peer_ = peer;
    peer_len_ = peer_len;
    have_peer_ = true;
    return true;
}

bool UnixControlSocket::send_response(std::uint32_t command, std::uint32_t wire_length, std::int32_t result) {
    if (fd_ < 0 || !have_peer_) return false;

    // The original allocates 0x400 bytes for every response. The first and
    // third u32s are the command and signed result; the rest is reserved.
    std::uint8_t response[0x400]{};
    std::memcpy(response, &command, sizeof(command));
    std::memcpy(response + 4, &wire_length, sizeof(wire_length));
    std::memcpy(response + 8, &result, sizeof(result));

    ssize_t n = -1;
    // Original daemon sends every response to the fixed cnss_user_client path.
    std::string client = path_;
    const auto pos = client.rfind("server");
    if (pos != std::string::npos) client.replace(pos, 6, "client");
    sockaddr_un dst{}; dst.sun_family = AF_UNIX;
    bool fixed_ok = false;
    if (client.size() < sizeof(dst.sun_path)) {
        std::memcpy(dst.sun_path, client.c_str(), client.size()+1);
        n = ::sendto(fd_, response, sizeof(response), 0,
                     reinterpret_cast<const sockaddr*>(&dst), sizeof(dst));
        fixed_ok = (n == static_cast<ssize_t>(sizeof(response)));
    }
    if (!fixed_ok && have_peer_) {
        n = ::sendto(fd_, response, sizeof(response), 0,
                     reinterpret_cast<const sockaddr*>(&peer_), peer_len_);
    }
    if (n < 0) {
        log(LogLevel::Warn, "Failed to send to user socket: %s", std::strerror(errno));
        return false;
    }
    log(LogLevel::Debug, "Sending Response for type %u", command);
    return n == static_cast<ssize_t>(sizeof(response));
}

} // namespace cnss
