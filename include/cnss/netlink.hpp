#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <array>

namespace cnss {

class GenericNetlink {
public:
    GenericNetlink() = default;
    ~GenericNetlink();
    GenericNetlink(const GenericNetlink&) = delete;
    GenericNetlink& operator=(const GenericNetlink&) = delete;

    bool open();
    bool resolve_family(const std::string& family);
    bool resolve_group(const std::string& family, const std::string& group);
    bool join_group(uint32_t group_id);
    bool send_vendor_command(uint32_t ifindex, uint32_t vendor_id, uint32_t subcmd,
                             const std::vector<std::array<std::uint8_t, 6>>& macs,
                             int timeout_ms = 1000);
    int fd() const noexcept { return fd_; }
    uint16_t family_id() const noexcept { return family_id_; }
    uint32_t group_id() const noexcept { return group_id_; }
    bool recv(std::vector<std::uint8_t>& packet, int timeout_ms);

private:
    int fd_{-1};
    uint16_t family_id_{0};
    uint32_t group_id_{0};
};

} // namespace cnss
