#pragma once
#include "cnss/netlink.hpp"
#include "cnss/qmi.hpp"
#include "cnss/unix_socket.hpp"
#include "cnss/event_registry.hpp"
#include "cnss/platform.hpp"
#include "cnss/neighbor_watch.hpp"
#include <cstdint>
#include <vector>
#include <atomic>
#include <memory>
#include <string>
#include <array>
#include <mutex>

namespace cnss {

struct Config {
    bool daemonize{true};
    bool no_kmsg{false};
    int debug_level{3};
    std::string user_socket{ "/data/vendor/wifi/sockets/cnss_user_server" };
    std::string qdss_cfg{ "/vendor/firmware_mnt/image/qdss_trace_config.cfg" };
    std::string qdss_fallback{ "/data/vendor/wifi/qdss_trace_config.bin" };
    std::string platform_dir{ "/veid/modem/wlan" };
};

class Daemon {
public:
    explicit Daemon(Config config);
    int run();
    void request_stop() noexcept;
    static void signal_handler(int sig) noexcept;
private:
    bool init_netlink();
    bool init_user_socket();
    void handle_user_packet();
    void handle_netlink_packet(const std::vector<std::uint8_t>& packet);
    void handle_cnss_genl_packet(const std::vector<std::uint8_t>& packet);
    void handle_wlan_svc_packet(const std::vector<std::uint8_t>& packet);
    void handle_nl80211_packet(const std::vector<std::uint8_t>& packet);
    void handle_neighbor_packet();
    void provision_dms();
    void register_indications();
    void handle_wlan_service_indication(std::uint16_t type, const std::uint8_t* data, std::size_t len);
    bool handle_wlan_dp_message(std::uint16_t type, const std::uint8_t* data, std::size_t len);
    void send_wlan_status_or_version(bool version);
    void handle_hang_event(const std::vector<std::uint8_t>& vdata);
    void handle_iot_event(const std::vector<std::uint8_t>& vdata);
    bool save_iot_table();
    bool load_iot_table();
    void pm_init_fallback();
    bool start_wlfw();
    void cleanup();

    Config config_;
    GenericNetlink cnss_genl_;
    GenericNetlink nl80211_;
    GenericNetlink wlan_svc_;
    NeighborWatch neighbor_watch_;
    UnixControlSocket user_socket_;
    WlfwClient wlfw_;
    std::atomic<bool> stop_{false};
    int nl80211_family_{-1};
    bool wlfw_started_{false};
    std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>> cnss_segments_;
    IndicationRegistry indications_;
    std::vector<std::uint8_t> qdss_config_;
    std::array<std::array<std::uint8_t, 6>, 20> iot_ap_table_{};
    std::size_t iot_ap_count_{0};
    std::array<std::uint8_t, 6> iot_trigger_mac_{};
    bool iot_trigger_valid_{false};
    std::vector<std::uint8_t> wlan_status_blob_;
    std::array<std::vector<std::uint8_t>, 9> wlan_status_segments_{};
    bool wlan_status_seen_{false};
    std::array<std::uint8_t, 0x44> wlan_version_blob_{};
    bool wlan_version_seen_{false};
    std::string tcp_adv_win_scale_saved_;
    bool tcp_adv_win_scale_saved_valid_{false};
    std::mutex service_mutex_;
    bool pm_voted_{false};
    std::uint32_t pm_modem_type_{0};
    std::string pm_modem_name_;
    static Daemon* instance_;
};

} // namespace cnss
