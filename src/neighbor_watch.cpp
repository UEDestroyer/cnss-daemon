#include "cnss/neighbor_watch.hpp"
#include "cnss/logger.hpp"
#include "cnss/platform.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sstream>
#include <sys/socket.h>
#include <unistd.h>

namespace cnss {
namespace {
constexpr std::size_t NLMSG_BUFFER = 1 << 16;

inline int rta_len(const rtattr* a) { return static_cast<int>(a->rta_len) - static_cast<int>(RTA_LENGTH(0)); }
inline const void* rta_data(const rtattr* a) { return RTA_DATA(const_cast<rtattr*>(a)); }

std::string mac_str(const std::uint8_t* m) {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
    return buf;
}
} // namespace

NeighborWatch::~NeighborWatch() { close(); }

bool NeighborWatch::open() {
    if (fd_ >= 0) return true;
    fd_ = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
    if (fd_ < 0) {
        log(LogLevel::Warn, "NeighborWatch: socket() failed: %s", std::strerror(errno));
        return false;
    }
    sockaddr_nl addr{};
    addr.nl_family = AF_NETLINK;
    // RTNLGRP_NEIGH (3) mirrors the original's neighbor-update subscription.
    // RTNLGRP_IPV4_ROUTE (25) / RTNLGRP_IPV6_ROUTE (27) are joined too so the
    // socket sees the same RTM_NEWROUTE traffic the original loop polled on
    // the same fd, even though this port does not decode the route table
    // (see the header comment on NeighborWatch for why).
    addr.nl_groups = (1u << (RTNLGRP_NEIGH - 1)) | (1u << (RTNLGRP_IPV4_ROUTE - 1)) |
                      (1u << (RTNLGRP_IPV6_ROUTE - 1));
    if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        log(LogLevel::Warn, "NeighborWatch: bind() failed: %s", std::strerror(errno));
        ::close(fd_);
        fd_ = -1;
        return false;
    }
    log(LogLevel::Info, "NeighborWatch: rtnetlink neighbor monitor active");
    return true;
}

void NeighborWatch::close() {
    if (fd_ >= 0) ::close(fd_);
    fd_ = -1;
}

std::vector<NeighborWatch::Entry> NeighborWatch::poll_reachable() {
    std::vector<Entry> out;
    if (fd_ < 0) return out;

    std::vector<std::uint8_t> buf(NLMSG_BUFFER);
    for (;;) {
        const ssize_t n = ::recv(fd_, buf.data(), buf.size(), 0);
        if (n < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) log(LogLevel::Warn, "NeighborWatch: recv() failed: %s", std::strerror(errno));
            break;
        }
        if (n == 0) break;

        auto* nlh = reinterpret_cast<nlmsghdr*>(buf.data());
        auto remaining = static_cast<std::size_t>(n);
        for (; NLMSG_OK(nlh, remaining); nlh = NLMSG_NEXT(nlh, remaining)) {
            if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) continue;
            if (nlh->nlmsg_type != RTM_NEWNEIGH && nlh->nlmsg_type != RTM_DELNEIGH) continue;

            const auto* ndm = static_cast<const ndmsg*>(NLMSG_DATA(nlh));
            if (ndm->ndm_family != AF_INET && ndm->ndm_family != AF_INET6) continue;

            Entry e;
            e.ifindex = ndm->ndm_ifindex;
            e.is_ipv6 = (ndm->ndm_family == AF_INET6);

            const auto* rta = reinterpret_cast<const rtattr*>(reinterpret_cast<const std::uint8_t*>(ndm) + NLMSG_ALIGN(sizeof(ndmsg)));
            int rem = static_cast<int>(NLMSG_PAYLOAD(nlh, sizeof(ndmsg)));
            for (; RTA_OK(rta, rem); rta = RTA_NEXT(rta, rem)) {
                if (rta->rta_type == NDA_DST) {
                    const int l = rta_len(rta);
                    if (!e.is_ipv6 && l >= 4) {
                        std::memcpy(e.addr.data(), rta_data(rta), 4);
                        char ip[INET_ADDRSTRLEN]{};
                        ::inet_ntop(AF_INET, e.addr.data(), ip, sizeof(ip));
                        e.addr_str = ip;
                    } else if (e.is_ipv6 && l >= 16) {
                        std::memcpy(e.addr.data(), rta_data(rta), 16);
                        char ip[INET6_ADDRSTRLEN]{};
                        ::inet_ntop(AF_INET6, e.addr.data(), ip, sizeof(ip));
                        e.addr_str = ip;
                    }
                } else if (rta->rta_type == NDA_LLADDR) {
                    if (rta_len(rta) >= 6) {
                        std::memcpy(e.lladdr.data(), rta_data(rta), 6);
                        e.has_lladdr = true;
                    }
                }
            }

            // NUD_REACHABLE (0x02) is the original's trigger for pushing a
            // resolved neighbor onward (see __parse_neighbor_data's
            // ndm_state == 2 branch). NUD_* values are kernel UAPI, not
            // proprietary, so this comparison is exact, unlike the
            // downstream vendor notification the original performs next.
            if (nlh->nlmsg_type == RTM_NEWNEIGH && (ndm->ndm_state & NUD_REACHABLE) && !e.addr_str.empty()) {
                const std::string base = platform::base_dir() + "/neighbors";
                const std::string key = std::to_string(e.ifindex) + (e.is_ipv6 ? "-v6" : "-v4");
                platform::write_text(base + "/" + key + ".ip", e.addr_str + "\n");
                if (e.has_lladdr) platform::write_text(base + "/" + key + ".mac", mac_str(e.lladdr.data()) + "\n");
                log(LogLevel::Debug, "NeighborWatch: ifindex=%d reachable %s%s%s", e.ifindex, e.addr_str.c_str(),
                    e.has_lladdr ? " mac=" : "", e.has_lladdr ? mac_str(e.lladdr.data()).c_str() : "");
                out.push_back(e);
            }
        }
    }
    return out;
}

} // namespace cnss
