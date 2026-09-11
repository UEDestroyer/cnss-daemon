#include "cnss/netlink.hpp"
#include "cnss/logger.hpp"
#include <cerrno>
#include <cstring>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/nl80211.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace cnss {
namespace {
constexpr std::size_t NLMSG_BUFFER = 1 << 16;

static inline int attr_len(const nlattr* a) { return static_cast<int>(a->nla_len) - NLA_HDRLEN; }
static inline void* attr_data(nlattr* a) { return reinterpret_cast<std::uint8_t*>(a) + NLA_HDRLEN; }
static inline const void* attr_data(const nlattr* a) { return reinterpret_cast<const std::uint8_t*>(a) + NLA_HDRLEN; }
static inline nlattr* attr_next(nlattr* a, int& rem) { int step = NLA_ALIGN(a->nla_len); rem -= step; return reinterpret_cast<nlattr*>(reinterpret_cast<std::uint8_t*>(a) + step); }
static inline const nlattr* attr_next(const nlattr* a, int& rem) { int step = NLA_ALIGN(a->nla_len); rem -= step; return reinterpret_cast<const nlattr*>(reinterpret_cast<const std::uint8_t*>(a) + step); }
static inline bool attr_ok(const nlattr* a, int rem) { return rem >= NLA_HDRLEN && a->nla_len >= NLA_HDRLEN && a->nla_len <= rem; }

bool put_attr(std::vector<std::uint8_t>& b, std::uint16_t type, const void* data, std::size_t len) {
    const std::size_t off = b.size();
    const std::size_t total = NLA_HDRLEN + len;
    const std::size_t padded = NLMSG_ALIGN(total);
    b.resize(off + padded, 0);
    auto* a = reinterpret_cast<nlattr*>(b.data() + off);
    a->nla_type = type;
    a->nla_len = static_cast<std::uint16_t>(total);
    std::memcpy(reinterpret_cast<std::uint8_t*>(a) + NLA_HDRLEN, data, len);
    return true;
}

} // namespace

GenericNetlink::~GenericNetlink() { if (fd_ >= 0) ::close(fd_); }

bool GenericNetlink::open() {
    if (fd_ >= 0) return true;
    fd_ = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (fd_ < 0) { log(LogLevel::Error, "socket(AF_NETLINK): %s", std::strerror(errno)); return false; }
    sockaddr_nl addr{}; addr.nl_family = AF_NETLINK; addr.nl_pid = 0;
    if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        log(LogLevel::Error, "bind(NETLINK_GENERIC): %s", std::strerror(errno)); ::close(fd_); fd_ = -1; return false;
    }
    return true;
}

bool GenericNetlink::resolve_family(const std::string& family) {
    if (!open()) return false;
    std::vector<std::uint8_t> msg(NLMSG_SPACE(GENL_HDRLEN));
    auto* nh = reinterpret_cast<nlmsghdr*>(msg.data());
    nh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN); nh->nlmsg_type = GENL_ID_CTRL;
    nh->nlmsg_flags = NLM_F_REQUEST; nh->nlmsg_seq = 1; nh->nlmsg_pid = static_cast<std::uint32_t>(::getpid());
    auto* gh = reinterpret_cast<genlmsghdr*>(NLMSG_DATA(nh));
    gh->cmd = CTRL_CMD_GETFAMILY; gh->version = 1;
    put_attr(msg, CTRL_ATTR_FAMILY_NAME, family.c_str(), family.size() + 1);
    nh = reinterpret_cast<nlmsghdr*>(msg.data());
    nh->nlmsg_len = static_cast<std::uint32_t>(msg.size());
    sockaddr_nl dst{}; dst.nl_family = AF_NETLINK;
    if (::sendto(fd_, msg.data(), nh->nlmsg_len, 0, reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) < 0) {
        log(LogLevel::Error, "resolve family %s: %s", family.c_str(), std::strerror(errno)); return false;
    }
    std::vector<std::uint8_t> rx(NLMSG_BUFFER);
    ssize_t n = ::recv(fd_, rx.data(), rx.size(), 0);
    if (n < static_cast<ssize_t>(NLMSG_LENGTH(GENL_HDRLEN))) return false;
    int rem_nl = static_cast<int>(n);
    for (auto* r = reinterpret_cast<nlmsghdr*>(rx.data()); NLMSG_OK(r, rem_nl); r = NLMSG_NEXT(r, rem_nl)) {
        if (r->nlmsg_type == NLMSG_ERROR) return false;
        auto* g = reinterpret_cast<genlmsghdr*>(NLMSG_DATA(r));
        const int payload = static_cast<int>(r->nlmsg_len) - static_cast<int>(NLMSG_LENGTH(GENL_HDRLEN));
        int rem = payload;
        for (auto* a = reinterpret_cast<nlattr*>(reinterpret_cast<std::uint8_t*>(g) + GENL_HDRLEN); attr_ok(a, rem); a = attr_next(a, rem)) {
            if (a->nla_type == CTRL_ATTR_FAMILY_ID && attr_len(a) >= 2) { std::memcpy(&family_id_, attr_data(a), 2); return true; }
        }
    }
    return false;
}

bool GenericNetlink::resolve_group(const std::string& family, const std::string& group) {
    // Resolve GROUPS from CTRL_CMD_GETFAMILY. This is enough for cnss-genl on kernels
    // that expose CTRL_ATTR_MCAST_GROUPS normally.
    if (!open()) return false;
    std::vector<std::uint8_t> msg(NLMSG_SPACE(GENL_HDRLEN));
    auto* nh = reinterpret_cast<nlmsghdr*>(msg.data());
    nh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN); nh->nlmsg_type = GENL_ID_CTRL; nh->nlmsg_flags = NLM_F_REQUEST;
    nh->nlmsg_seq = 2; nh->nlmsg_pid = static_cast<std::uint32_t>(::getpid());
    auto* gh = reinterpret_cast<genlmsghdr*>(NLMSG_DATA(nh)); gh->cmd = CTRL_CMD_GETFAMILY; gh->version = 1;
    put_attr(msg, CTRL_ATTR_FAMILY_NAME, family.c_str(), family.size()+1);
    nh = reinterpret_cast<nlmsghdr*>(msg.data());
    nh->nlmsg_len = static_cast<std::uint32_t>(msg.size());
    sockaddr_nl dst{}; dst.nl_family = AF_NETLINK;
    if (::sendto(fd_, msg.data(), nh->nlmsg_len, 0, reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) < 0) return false;
    std::vector<std::uint8_t> rx(NLMSG_BUFFER); ssize_t n = ::recv(fd_, rx.data(), rx.size(), 0);
    if (n < 0) return false;
    int rem_nl = static_cast<int>(n);
    for (auto* r = reinterpret_cast<nlmsghdr*>(rx.data()); NLMSG_OK(r, rem_nl); r = NLMSG_NEXT(r, rem_nl)) {
        if (r->nlmsg_type == NLMSG_ERROR) return false;
        auto* g = reinterpret_cast<genlmsghdr*>(NLMSG_DATA(r)); int rem = static_cast<int>(r->nlmsg_len) - static_cast<int>(NLMSG_LENGTH(GENL_HDRLEN));
        for (auto* a = reinterpret_cast<nlattr*>(reinterpret_cast<std::uint8_t*>(g) + GENL_HDRLEN); attr_ok(a, rem); a = attr_next(a, rem)) {
            if (a->nla_type != CTRL_ATTR_MCAST_GROUPS) continue;
            int grem = attr_len(a); auto* ga = reinterpret_cast<nlattr*>(attr_data(a));
            for (; attr_ok(ga, grem); ga = attr_next(ga, grem)) {
                int arem = attr_len(ga); auto* ma = reinterpret_cast<nlattr*>(attr_data(ga)); std::string name; uint32_t id = 0;
                for (; attr_ok(ma, arem); ma = attr_next(ma, arem)) {
                    if (ma->nla_type == CTRL_ATTR_MCAST_GRP_NAME) name = reinterpret_cast<const char*>(attr_data(ma));
                    else if (ma->nla_type == CTRL_ATTR_MCAST_GRP_ID && attr_len(ma) >= 4) std::memcpy(&id, attr_data(ma), 4);
                }
                if (name == group) { group_id_ = id; return true; }
            }
        }
    }
    return false;
}

bool GenericNetlink::join_group(uint32_t group_id) {
    if (fd_ < 0 || group_id == 0) return false;
    if (::setsockopt(fd_, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group_id, sizeof(group_id)) < 0) {
        log(LogLevel::Error, "NETLINK_ADD_MEMBERSHIP %u: %s", group_id, std::strerror(errno)); return false;
    }
    return true;
}

bool GenericNetlink::recv(std::vector<std::uint8_t>& packet, int timeout_ms) {
    if (fd_ < 0) return false;
    pollfd p{fd_, POLLIN, 0}; const int rc = ::poll(&p, 1, timeout_ms);
    if (rc <= 0) return rc == 0;
    packet.resize(NLMSG_BUFFER); const ssize_t n = ::recv(fd_, packet.data(), packet.size(), 0);
    if (n < 0) return false;
    packet.resize(static_cast<std::size_t>(n));
    return true;
}
}


namespace cnss {
namespace {
bool nla_put_raw(std::vector<std::uint8_t>& b, std::uint16_t type, const void* data, std::size_t len) {
    const std::size_t off = b.size();
    const std::size_t total = NLA_HDRLEN + len;
    const std::size_t padded = NLA_ALIGN(total);
    if (total > 0xffffu) return false;
    b.resize(off + padded, 0);
    auto* a = reinterpret_cast<nlattr*>(b.data() + off);
    a->nla_len = static_cast<std::uint16_t>(total);
    a->nla_type = type;
    if (len) std::memcpy(reinterpret_cast<std::uint8_t*>(a) + NLA_HDRLEN, data, len);
    return true;
}

template <typename T>
bool nla_put_value(std::vector<std::uint8_t>& b, std::uint16_t type, T value) {
    return nla_put_raw(b, type, &value, sizeof(value));
}

bool nla_start_nested(std::vector<std::uint8_t>& b, std::uint16_t type, std::size_t& offset) {
    offset = b.size();
    return nla_put_raw(b, static_cast<std::uint16_t>(type | NLA_F_NESTED), nullptr, 0);
}

void nla_end_nested(std::vector<std::uint8_t>& b, std::size_t offset) {
    auto* a = reinterpret_cast<nlattr*>(b.data() + offset);
    a->nla_len = static_cast<std::uint16_t>(b.size() - offset);
}
}

bool GenericNetlink::send_vendor_command(uint32_t ifindex, uint32_t vendor_id, uint32_t subcmd,
                                          const std::vector<std::array<std::uint8_t, 6>>& macs,
                                          int timeout_ms) {
    if (fd_ < 0 || family_id_ == 0) return false;
    std::vector<std::uint8_t> msg(NLMSG_SPACE(GENL_HDRLEN), 0);
    auto* nh = reinterpret_cast<nlmsghdr*>(msg.data());
    nh->nlmsg_type = family_id_;
    nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nh->nlmsg_seq = 0xC001u;
    auto* gh = reinterpret_cast<genlmsghdr*>(NLMSG_DATA(nh));
    gh->cmd = NL80211_CMD_VENDOR;
    gh->version = 1;

    nla_put_value(msg, NL80211_ATTR_IFINDEX, ifindex);
    nla_put_value(msg, NL80211_ATTR_VENDOR_ID, vendor_id);
    nla_put_value(msg, NL80211_ATTR_VENDOR_SUBCMD, subcmd);

    std::size_t vendor_off = 0;
    if (!nla_start_nested(msg, NL80211_ATTR_VENDOR_DATA, vendor_off)) return false;
    std::size_t list_off = 0;
    if (!nla_start_nested(msg, 2, list_off)) return false;
    for (std::size_t i = 0; i < macs.size(); ++i) {
        std::size_t item_off = 0;
        if (!nla_start_nested(msg, static_cast<std::uint16_t>(i), item_off)) return false;
        if (!nla_put_raw(msg, 3, macs[i].data(), macs[i].size())) return false;
        nla_end_nested(msg, item_off);
    }
    nla_end_nested(msg, list_off);
    nla_end_nested(msg, vendor_off);

    nh = reinterpret_cast<nlmsghdr*>(msg.data());
    nh->nlmsg_len = static_cast<std::uint32_t>(msg.size());
    sockaddr_nl dst{};
    dst.nl_family = AF_NETLINK;
    if (::sendto(fd_, msg.data(), nh->nlmsg_len, 0, reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) < 0) {
        log(LogLevel::Warn, "nl80211 vendor send: %s", std::strerror(errno));
        return false;
    }

    std::vector<std::uint8_t> rx(NLMSG_BUFFER);
    pollfd pfd{fd_, POLLIN, 0};
    if (::poll(&pfd, 1, timeout_ms) <= 0) return false;
    const ssize_t n = ::recv(fd_, rx.data(), rx.size(), 0);
    if (n < static_cast<ssize_t>(NLMSG_HDRLEN)) return false;
    int rem = static_cast<int>(n);
    for (auto* r = reinterpret_cast<nlmsghdr*>(rx.data()); NLMSG_OK(r, rem); r = NLMSG_NEXT(r, rem)) {
        if (r->nlmsg_type != NLMSG_ERROR) continue;
        auto* err = reinterpret_cast<const nlmsgerr*>(NLMSG_DATA(r));
        if (!err || r->nlmsg_len < NLMSG_LENGTH(sizeof(nlmsgerr))) return false;
        if (err->error != 0) {
            log(LogLevel::Warn, "nl80211 vendor command failed: %d", err->error);
            return false;
        }
        return true;
    }
    return false;
}
} // namespace cnss
