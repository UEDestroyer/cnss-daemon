#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace cnss {

// Restores the source-recoverable core of the original cnss_gw_update_loop /
// __parse_neighbor_data / get_ip_from_neighbor_data functions: a raw
// NETLINK_ROUTE socket subscribed to RTNLGRP_NEIGH, decoding RTM_NEWNEIGH /
// RTM_DELNEIGH messages (standard rtnetlink ABI: struct ndmsg + NDA_DST /
// NDA_LLADDR attributes -- these constants are kernel UAPI, not proprietary,
// so they are reconstructed exactly rather than guessed).
//
// NOT reconstructed here (left as a documented gap, same category as the
// WLAN_MSG_SERVICE proprietary ID already called out in STATUS.md):
//   - RTM_NEWROUTE route-table tracking that runs alongside the neighbor
//     watch in the original (a 64-entry route table keyed by an internal,
//     never-named struct layout).
//   - The final step in the original, which forwards a reachable neighbor's
//     IP/MAC onward via a generic-netlink message with id 0x95. That id
//     does not belong to nl80211's public command set and the owning
//     genl family is never named in the decompiled text, so it cannot be
//     safely guessed -- sending an invalid command into the kernel netlink
//     path is worse than not sending one. See on_reachable_neighbor() below
//     for the integration point once that family/subcmd is known.
class NeighborWatch {
public:
    struct Entry {
        int ifindex{0};
        bool is_ipv6{false};
        std::array<std::uint8_t, 16> addr{};   // IPv4 in first 4 bytes, or full IPv6
        std::string addr_str;
        bool has_lladdr{false};
        std::array<std::uint8_t, 6> lladdr{};
    };

    NeighborWatch() = default;
    ~NeighborWatch();
    NeighborWatch(const NeighborWatch&) = delete;
    NeighborWatch& operator=(const NeighborWatch&) = delete;

    // Opens the NETLINK_ROUTE socket and joins RTNLGRP_NEIGH (and, best
    // effort, RTNLGRP_IPV4_ROUTE/RTNLGRP_IPV6_ROUTE so link-layer callers
    // can still see route churn even though we don't decode it -- matches
    // the original listening on the same socket for both message classes).
    bool open();
    void close();
    int fd() const noexcept { return fd_; }

    // Reads and decodes one batch of pending netlink messages. Returns the
    // neighbor entries that reached NUD_REACHABLE (mirrors the original's
    // trigger condition for pushing gateway info onward) since the previous
    // call. Persists every reachable entry to
    // <platform::base_dir()>/neighbors/<ifindex>-<family>.{ip,mac} so the
    // information survives even without the unresolved downstream vendor
    // notification.
    std::vector<Entry> poll_reachable();

private:
    int fd_{-1};
};

} // namespace cnss
