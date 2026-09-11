#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <sys/un.h>
#include <sys/socket.h>

namespace cnss {

// Wire format used by the original cnss-daemon:
//   u32 command
//   u32 payload_length
//   payload bytes
// Responses are always 0x400 bytes, with command at offset 0 and result at offset 8.
struct UserPacket {
    std::uint32_t command{};
    std::uint32_t wire_length{};
    std::vector<std::uint8_t> payload;
};

class UnixControlSocket {
public:
    ~UnixControlSocket();
    bool listen(const std::string& path);
    int fd() const noexcept { return fd_; }
    void close();
    bool recv_packet(UserPacket& packet);
    bool send_response(std::uint32_t command, std::uint32_t wire_length, std::int32_t result);
    const std::string& path() const noexcept { return path_; }

private:
    int fd_{-1};
    std::string path_;
    sockaddr_un peer_{};
    socklen_t peer_len_{0};
    bool have_peer_{false};
};

} // namespace cnss
