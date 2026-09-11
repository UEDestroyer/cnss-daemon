#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace cnss {

struct WlfwCapability {
    bool chip_valid{false};
    std::uint32_t chip_id{0};
    std::uint32_t chip_family{0};
    bool board_valid{false};
    std::uint32_t board_id{0};
    bool soc_valid{false};
    std::uint32_t soc_id{0};
    bool fw_version_valid{false};
    std::uint32_t fw_version{0};
    std::string fw_build_timestamp;
    bool build_id_valid{false};
    std::string build_id;
    bool num_macs_valid{false};
    std::uint8_t num_macs{0};
};

class CalibrationTable {
public:
    void reset();
    bool load(const std::string& directory);
    const std::vector<std::uint8_t>& blob(std::size_t index) const;
    std::vector<std::uint32_t> present_ids() const;

private:
    std::array<std::vector<std::uint8_t>, 5> entries_{};
};

class WlfwClient {
public:
    using IndicationCallback = std::function<void(std::uint16_t,
                                                   const std::vector<std::uint8_t>&)>;

    WlfwClient();
    ~WlfwClient();

    WlfwClient(const WlfwClient&) = delete;
    WlfwClient& operator=(const WlfwClient&) = delete;

    bool start();
    void stop();
    bool connected() const noexcept;

    void set_indication_callback(IndicationCallback cb);

    bool send_capability_request();
    bool send_calibration_report();
    bool send_indication_register(std::uint64_t& fw_status);
    bool send_bdf_download(std::uint32_t bdf_type, const std::string& name);
    bool send_qdss_trace_mode(std::uint32_t mode, std::uint64_t option);
    bool send_qdss_trace_config(const std::vector<std::uint8_t>& config);
    bool send_mac_address(const std::array<std::uint8_t, 6>& mac);
    bool handle_qdss_trace_save_indication(const std::vector<std::uint8_t>& payload);

    // Reloads /data/vendor/wifi/wlfw_cal_NN.bin (NN = 00..04) into the
    // in-memory calibration table used by handle_cal_download_indication().
    void reload_calibration_table();
    // FW requests its calibration blob for cal_id via an indication; this
    // sends it back chunked over WLFW_CAL_DOWNLOAD_REQ (0x27), retrying on
    // QMI_ERR_FW_BUSY the way the original does (4 attempts, 500ms*attempt).
    bool handle_cal_download_indication(std::uint32_t cal_id);
    // FW pushes a fresh calibration blob to us via CAL_UPDATE_REQ_IND (0x2a);
    // pull it back seg-by-seg over WLFW_CAL_UPDATE_REQ (0x29) and persist it
    // to /data/vendor/wifi/wlfw_cal_NN.bin so the next boot's download uses it.
    bool handle_cal_update_indication(std::uint32_t cal_id, std::uint32_t total_size);
    bool send_raw(std::uint16_t msg_id, const void* req, std::size_t req_len,
                  void* rsp = nullptr, std::size_t rsp_len = 0);

    bool wait_for_state(std::uint64_t mask, std::chrono::milliseconds timeout);
    // Re-issue IND_REGISTER and refresh the FW status bitmap.  FW_IS_READY is
    // reported in this bitmap rather than as a standalone indication.
    bool refresh_fw_status(std::uint64_t& fw_status);
    bool wait_for_fw_ready(std::chrono::milliseconds timeout);
    std::uint64_t state() const noexcept;
    const WlfwCapability& capability() const noexcept { return capability_; }

    static std::array<std::uint8_t, 32> build_qdss_trace_mode_request(
        std::uint32_t mode, std::uint64_t option, std::uint32_t hw_override);


    bool send_mac_addr(const std::array<std::uint8_t, 6>& mac);
    int fd() const { return fd_; } // Геттер для получения номера сокета
    std::uint32_t instance_id() const noexcept { return instance_id_; }

private:
    struct Pending;

    bool lookup_service(std::uint32_t wanted_instance, std::uint32_t& node, std::uint32_t& port,
                        std::uint32_t& instance);
    bool open_qrtr();
    void rx_loop();
    void dispatch_message(const std::vector<std::uint8_t>& packet);
    bool send_packet(const std::vector<std::uint8_t>& packet);
    bool request(std::uint16_t msg_id, const std::vector<std::uint8_t>& payload,
                 std::vector<std::uint8_t>& response);
    static bool parse_result(const std::vector<std::uint8_t>& payload,
                             std::uint16_t& result, std::uint16_t& error);
    static void put_u16_le(std::uint8_t* p, std::uint16_t v);
    static void put_u32_le(std::uint8_t* p, std::uint32_t v);
    static void put_u64_le(std::uint8_t* p, std::uint64_t v);
    static std::uint16_t get_u16_le(const std::uint8_t* p);
    static std::uint32_t get_u32_le(const std::uint8_t* p);
    static std::uint64_t get_u64_le(const std::uint8_t* p);
    static void add_tlv(std::vector<std::uint8_t>& out, std::uint8_t type,
                        const void* data, std::size_t len);
    static void add_tlv_u8(std::vector<std::uint8_t>& out, std::uint8_t type, std::uint8_t v);
    static void add_tlv_u32(std::vector<std::uint8_t>& out, std::uint8_t type, std::uint32_t v);

    mutable std::mutex mutex_;
    std::mutex pending_mutex_;
    std::mutex tx_mutex_;
    std::condition_variable state_cv_;
    std::thread rx_thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> connected_{false};
    int fd_{-1};
    std::uint32_t server_node_{0};
    std::uint32_t server_port_{0};
    std::uint32_t instance_id_{0};
    std::uint16_t next_txn_{1};
    std::uint64_t state_{0};
    WlfwCapability capability_{};
    IndicationCallback indication_cb_{};
    std::vector<std::shared_ptr<Pending>> pending_;
    std::mutex cal_mutex_;
    CalibrationTable cal_table_;
    std::mutex worker_mutex_;
    std::vector<std::thread> workers_;

    bool send_cal_chunk(std::uint32_t cal_id, const std::uint8_t* data, std::size_t total_size,
                        std::size_t len, std::size_t offset, std::uint32_t seg, bool last);
    // Requests one segment of a FW-pushed calibration blob (WLFW_CAL_UPDATE_REQ,
    // 0x29). Fills `out_chunk` with the segment payload and sets `last` when the
    // FW reports this was the final segment. Retries on QMI_ERR_FW_BUSY like
    // send_cal_chunk() does.
    bool request_cal_update_chunk(std::uint32_t cal_id, std::uint32_t seg,
                                  std::vector<std::uint8_t>& out_chunk, bool& last);
};


class DmsClient {
public:
    DmsClient() = default;
    ~DmsClient();
    DmsClient(const DmsClient&) = delete;
    DmsClient& operator=(const DmsClient&) = delete;

    bool start();
    void stop();
    bool get_mac(bool bluetooth, std::array<std::uint8_t, 6>& mac);

private:
    bool lookup_service(std::uint32_t& node, std::uint32_t& port);
    bool request(std::uint16_t msg_id, const std::vector<std::uint8_t>& payload,
                 std::vector<std::uint8_t>& response, std::chrono::milliseconds timeout);
    bool send_packet(const std::vector<std::uint8_t>& packet);
    static bool parse_result(const std::vector<std::uint8_t>& payload,
                             std::uint16_t& result, std::uint16_t& error);
    static std::uint16_t get_u16_le(const std::uint8_t* p);
    static std::uint32_t get_u32_le(const std::uint8_t* p);

    int fd_{-1};
    std::uint32_t node_{0};
    std::uint32_t port_{0};
    std::uint16_t txn_{1};
};

} // namespace cnss
