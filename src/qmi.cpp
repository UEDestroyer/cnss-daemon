#include "cnss/qmi.hpp"
#include "cnss/logger.hpp"
#include "cnss/platform.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cerrno>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <linux/qrtr.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdlib>
#include <string>
#include <vector>

namespace cnss {
namespace {

#ifndef AF_QIPCRTR
#define AF_QIPCRTR 42
#endif

// QRTR control packet on-wire layout (service, instance, node, port) — the
// same layout the working reference script uses.  We deliberately do NOT use
// <linux/qrtr.h>'s qrtr_ctrl_pkt here: toolchain headers have shipped with
// different field orders, which corrupts instance/node/port reads.
struct QrtrCtrlPkt {
    std::uint32_t cmd;
    struct {
        std::uint32_t service;   // offset 4
        std::uint32_t version;   // offset 8
        std::uint32_t instance;  // offset 12
        std::uint32_t port;      // offset 16
    } server;
};
constexpr std::uint32_t QRTR_TYPE_NEW_SERVER = 4;
constexpr std::uint32_t QRTR_TYPE_NEW_LOOKUP = 10;

constexpr std::uint32_t QRTR_INSTANCE_ANY = 0; // the working script sends instance=0
constexpr std::uint32_t WLFW_SERVICE = 0x45u;
constexpr std::uint16_t WLFW_IND_REGISTER_REQ = 0x20;
constexpr std::uint16_t WLFW_BDF_DOWNLOAD_REQ = 0x25;
constexpr std::uint16_t WLFW_CAL_REPORT_REQ = 0x26;
constexpr std::uint16_t WLFW_CAL_DOWNLOAD_REQ = 0x27;
constexpr std::uint16_t WLFW_CAL_UPDATE_REQ = 0x29;   // QMI_WLFW_CAL_UPDATE_REQ_V01
constexpr std::uint16_t QMI_ERR_FW_BUSY = 2;
constexpr std::uint16_t WLFW_CAP_REQ = 0x24;
constexpr std::uint16_t WLFW_QDSS_TRACE_DATA_REQ = 0x42;
constexpr std::uint16_t WLFW_QDSS_TRACE_CONFIG_DOWNLOAD_REQ = 0x44;
constexpr std::uint16_t WLFW_QDSS_TRACE_MODE_REQ = 0x45;
constexpr std::size_t QDSS_CHUNK = 0x1800;
constexpr std::size_t BDF_CHUNK = 0x1800;
constexpr std::uint64_t STATE_CONNECTED = 1ull << 0;
// WLFW IND_REGISTER response fw_status bits (from the reference cnss-daemon):
// bit 1 = FW_IS_READY, bit 2 = MSA_READY, bit 3 = FW_MEMORY_READY.
constexpr std::uint64_t STATE_FW_READY  = 1ull << 1;
constexpr std::uint64_t STATE_MSA_READY = 1ull << 2;
constexpr std::uint64_t STATE_MEM_READY = 1ull << 3;

#pragma pack(push, 1)
struct QmiHeader {
    std::uint8_t type;
    std::uint16_t txn_id;
    std::uint16_t msg_id;
    std::uint16_t msg_len;
};
#pragma pack(pop)

static_assert(sizeof(QmiHeader) == 7, "unexpected QMI header packing");

struct QrtrLookup {
    sockaddr_qrtr address{};
};

std::uint32_t env_u32(const char* name, std::uint32_t fallback) {
    const char* s = std::getenv(name);
    if (!s || !*s) return fallback;
    char* end = nullptr;
    errno = 0;
    const unsigned long v = std::strtoul(s, &end, 0);
    if (errno != 0 || end == s) return fallback;
    return static_cast<std::uint32_t>(v);
}

std::uint32_t read_hw_override() {
    return std::min<std::uint32_t>(env_u32("CNSS_HW_TRAC_DISABLE_OVERRIDE", 0), 2);
}

std::string read_file_name(const std::vector<std::string>& paths, std::string* found) {
    for (const auto& p : paths) {
        std::ifstream in(p, std::ios::binary);
        if (in) {
            if (found) *found = p;
            return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
        }
    }
    return {};
}

std::string hex_str(const std::vector<std::uint8_t>& v) {
    static const char* digits = "0123456789abcdef";
    std::string s;
    s.reserve(v.size() * 3);
    for (std::uint8_t b : v) {
        s.push_back(digits[b >> 4]);
        s.push_back(digits[b & 0x0f]);
        s.push_back(' ');
    }
    if (!s.empty()) s.pop_back();
    return s;
}

} // namespace

struct WlfwClient::Pending {
    std::uint16_t txn{0};
    std::uint16_t msg_id{0};
    std::vector<std::uint8_t> response;
    bool done{false};
    std::condition_variable cv;
};

WlfwClient::WlfwClient() = default;

WlfwClient::~WlfwClient() {
    stop();
}

void WlfwClient::put_u16_le(std::uint8_t* p, std::uint16_t v) {
    p[0] = static_cast<std::uint8_t>(v);
    p[1] = static_cast<std::uint8_t>(v >> 8);
}

void WlfwClient::put_u32_le(std::uint8_t* p, std::uint32_t v) {
    p[0] = static_cast<std::uint8_t>(v);
    p[1] = static_cast<std::uint8_t>(v >> 8);
    p[2] = static_cast<std::uint8_t>(v >> 16);
    p[3] = static_cast<std::uint8_t>(v >> 24);
}

void WlfwClient::put_u64_le(std::uint8_t* p, std::uint64_t v) {
    for (unsigned i = 0; i < 8; ++i) p[i] = static_cast<std::uint8_t>(v >> (i * 8));
}

std::uint16_t WlfwClient::get_u16_le(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(p[0] | (static_cast<std::uint16_t>(p[1]) << 8));
}

std::uint32_t WlfwClient::get_u32_le(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint64_t WlfwClient::get_u64_le(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (unsigned i = 0; i < 8; ++i) v |= static_cast<std::uint64_t>(p[i]) << (i * 8);
    return v;
}

void WlfwClient::add_tlv(std::vector<std::uint8_t>& out, std::uint8_t type,
                         const void* data, std::size_t len) {
    if (len > 0xffffu) throw std::runtime_error("QMI TLV too large");
    const auto old = out.size();
    out.resize(old + 3 + len);
    out[old] = type;
    put_u16_le(out.data() + old + 1, static_cast<std::uint16_t>(len));
    if (len) std::memcpy(out.data() + old + 3, data, len);
}

void WlfwClient::add_tlv_u8(std::vector<std::uint8_t>& out, std::uint8_t type, std::uint8_t v) {
    add_tlv(out, type, &v, sizeof(v));
}

void WlfwClient::add_tlv_u32(std::vector<std::uint8_t>& out, std::uint8_t type, std::uint32_t v) {
    std::array<std::uint8_t, 4> b{};
    put_u32_le(b.data(), v);
    add_tlv(out, type, b.data(), b.size());
}

// Reads a mandatory u32 TLV of the given type out of a QMI indication payload.
bool find_tlv_u32(const std::vector<std::uint8_t>& payload, std::uint8_t type, std::uint32_t& value) {
    std::size_t off = 0;
    while (off + 3 <= payload.size()) {
        const std::uint8_t t = payload[off];
        const std::uint16_t len = static_cast<std::uint16_t>(payload[off + 1] | (payload[off + 2] << 8));
        off += 3;
        if (off + len > payload.size()) return false;
        if (t == type && len >= 4) {
            value = static_cast<std::uint32_t>(payload[off]) | (static_cast<std::uint32_t>(payload[off + 1]) << 8) |
                    (static_cast<std::uint32_t>(payload[off + 2]) << 16) | (static_cast<std::uint32_t>(payload[off + 3]) << 24);
            return true;
        }
        off += len;
    }
    return false;
}

bool find_tlv_u8(const std::vector<std::uint8_t>& payload, std::uint8_t type, std::uint8_t& value) {
    std::size_t off = 0;
    while (off + 3 <= payload.size()) {
        const std::uint8_t t = payload[off];
        const std::uint16_t len = static_cast<std::uint16_t>(payload[off + 1] | (payload[off + 2] << 8));
        off += 3;
        if (off + len > payload.size()) return false;
        if (t == type && len >= 1) {
            value = payload[off];
            return true;
        }
        off += len;
    }
    return false;
}
// Reads an optional TLV of the given type, returning its raw bytes verbatim.
bool find_tlv_bytes(const std::vector<std::uint8_t>& payload, std::uint8_t type,
                    std::vector<std::uint8_t>& out) {
    std::size_t off = 0;
    while (off + 3 <= payload.size()) {
        const std::uint8_t t = payload[off];
        const std::uint16_t len = static_cast<std::uint16_t>(payload[off + 1] | (payload[off + 2] << 8));
        off += 3;
        if (off + len > payload.size()) return false;
        if (t == type) {
            out.assign(payload.begin() + static_cast<long>(off), payload.begin() + static_cast<long>(off) + len);
            return true;
        }
        off += len;
    }
    return false;
}

bool WlfwClient::open_qrtr() {
    fd_ = ::socket(AF_QIPCRTR, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd_ < 0) {
        log(LogLevel::Error, "WLFW: socket(AF_QIPCRTR) failed: %s", std::strerror(errno));
        return false;
    }

    struct sockaddr_qrtr addr;
    socklen_t alen = sizeof(addr);

    // ШАГ 1: Узнаем у ядра, какой node ID оно нам дало по умолчанию
    if (::getsockname(fd_, (struct sockaddr *)&addr, &alen) < 0) {
        log(LogLevel::Error, "WLFW: getsockname failed: %s", std::strerror(errno));
        ::close(fd_); fd_ = -1; return false;
    }

    log(LogLevel::Debug, "WLFW: Kernel assigned node: %u, port: %u", addr.sq_node, addr.sq_port);

    // ШАГ 2: Привязываемся (bind) именно к этому node, но порт просим 0 (динамический)
    addr.sq_family = AF_QIPCRTR;
    addr.sq_port = 0; 
    // sq_node остается тем, что мы получили из getsockname

    if (::bind(fd_, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log(LogLevel::Error, "WLFW: bind failed: %s", std::strerror(errno));
        ::close(fd_); fd_ = -1; return false;
    }

    return true;
}

bool WlfwClient::lookup_service(std::uint32_t wanted_instance,
                                std::uint32_t& node, std::uint32_t& port,
                                std::uint32_t& instance) {
    // QRTR lookup traffic is carried over the control port.  Do NOT use the
    // QMI data socket (fd_) for lookup: the QRTR NEW_SERVER control packet
    // would remain queued there and the RX thread would interpret its first
    // bytes as a QMI header.  That is exactly what produced:
    //   WLFW indication 0x0000 payload=0
    // Use a dedicated lookup socket, like Qualcomm's QCCI transport does.
    // See qcci_xport_qrtr.c: lookup_sock_fd is separate from each client
    // transport socket.
    const int lookup_fd = ::socket(AF_QIPCRTR, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (lookup_fd < 0) {
        log(LogLevel::Warn, "WLFW: QRTR lookup socket: %s", std::strerror(errno));
        return false;
    }

    // The working reference script BINDS the lookup socket (kernel-assigned
    // node, ephemeral port).  An unbound QRTR socket is treated as a control
    // socket and receives broadcast noise (all-zero NEW_SERVER packets)
    // instead of the directed lookup response.
    {
        sockaddr_qrtr local{};
        socklen_t alen = sizeof(local);
        if (::getsockname(lookup_fd, reinterpret_cast<sockaddr*>(&local), &alen) < 0) {
            local.sq_node = 0;
        }
        local.sq_family = AF_QIPCRTR;
        local.sq_port = 0; // kernel picks an ephemeral port
        if (::bind(lookup_fd, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) < 0) {
            log(LogLevel::Warn, "WLFW: QRTR lookup bind: %s", std::strerror(errno));
            ::close(lookup_fd);
            return false;
        }
    }

    sockaddr_qrtr ctrl{};
    ctrl.sq_family = AF_QIPCRTR;
    ctrl.sq_node = QRTR_NODE_BCAST;
    ctrl.sq_port = QRTR_PORT_CTRL;

    QrtrCtrlPkt lookup{};
    lookup.cmd = QRTR_TYPE_NEW_LOOKUP;
    lookup.server.service = WLFW_SERVICE;
    lookup.server.instance = 0; // the working script looks up instance 0

    if (::sendto(lookup_fd, &lookup, sizeof(lookup), 0,
                 reinterpret_cast<const sockaddr*>(&ctrl), sizeof(ctrl)) < 0) {
        log(LogLevel::Warn, "WLFW: QRTR service lookup: %s", std::strerror(errno));
        ::close(lookup_fd);
        return false;
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    std::array<std::uint8_t, 512> buf{};
    while (std::chrono::steady_clock::now() < deadline) {
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        pollfd pfd{lookup_fd, POLLIN, 0};
        const int ms = static_cast<int>(std::clamp<long long>(remaining, 1, 500));
        const int rc = ::poll(&pfd, 1, ms);
        if (rc <= 0) continue;
        sockaddr_qrtr src{};
        socklen_t srclen = sizeof(src);
        const ssize_t n = ::recvfrom(lookup_fd, buf.data(), buf.size(), 0,
                                     reinterpret_cast<sockaddr*>(&src), &srclen);
        if (n < static_cast<ssize_t>(sizeof(QrtrCtrlPkt))) continue;
        log(LogLevel::Debug, "WLFW: lookup rx %zd bytes from node=%u port=%u: %s",
            n, src.sq_node, src.sq_port,
            hex_str(std::vector<std::uint8_t>(buf.begin(), buf.begin() + n)).c_str());
        QrtrCtrlPkt pkt{};
        std::memcpy(&pkt, buf.data(), sizeof(pkt));
        if (pkt.cmd != QRTR_TYPE_NEW_SERVER) continue;
        const std::uint32_t service = pkt.server.service;
        const std::uint32_t pkt_version = pkt.server.version;
        const std::uint32_t pkt_instance = pkt.server.instance;
        const std::uint32_t pkt_port = pkt.server.port;
        log(LogLevel::Debug, "WLFW: NEW_SERVER service=0x%x version=0x%x instance=0x%x port=0x%x (src node=%u)",
            service, pkt_version, pkt_instance, pkt_port, src.sq_node);
        if (service != WLFW_SERVICE) continue;
        if (wanted_instance != QRTR_INSTANCE_ANY && pkt_instance != wanted_instance) continue;
        // The 20-byte lookup response carries {service, version, instance,
        // port} but NOT the service node (the node is only in the broadcast
        // NEW_SERVER that qrtr-lookup sees).  The WLAN firmware (WLFW) lives
        // on node 0 while the host daemon is on node 1, so use node 0.
        node = 0;
        port = pkt_port;
        instance = pkt_instance;
        ::close(lookup_fd);
        return true;
    }

    ::close(lookup_fd);
    log(LogLevel::Warn, "WLFW: service 0x%x instance 0x%x not found", WLFW_SERVICE, wanted_instance);
    return false;
}

bool WlfwClient::start() {
    std::lock_guard<std::mutex> lk(mutex_);
    if (connected_) return true;

    if (!open_qrtr()) return false;

    const std::uint32_t wanted = env_u32("CNSS_WLFW_INSTANCE", QRTR_INSTANCE_ANY);
    log(LogLevel::Debug, "WLFW: lookup wanted_instance=0x%x", wanted);
    std::uint32_t node = 0, port = 0, instance = 0;
    if (!lookup_service(wanted, node, port, instance)) {
        ::close(fd_);
        fd_ = -1;
        return false;
    }

    server_node_ = node;
    server_port_ = port;
    instance_id_ = instance;
    state_ = 0;
    connected_ = true;
    running_ = true;
    rx_thread_ = std::thread(&WlfwClient::rx_loop, this);

    log(LogLevel::Info, "WLFW service connected: node=%u port=%u instance=%u", node, port, instance);
    return true;
}

void WlfwClient::stop() {
    {
        std::lock_guard<std::mutex> lk(mutex_);
        if (!running_ && fd_ < 0) return;
        running_ = false;
        connected_ = false;
    }

    if (fd_ >= 0) {
        ::shutdown(fd_, SHUT_RDWR);
    }
    if (rx_thread_.joinable()) rx_thread_.join();
    {
        std::vector<std::thread> workers;
        { std::lock_guard<std::mutex> lk(worker_mutex_); workers.swap(workers_); }
        for (auto& worker : workers) if (worker.joinable()) worker.join();
    }
    if (fd_ >= 0) ::close(fd_);
    fd_ = -1;

    {
        std::lock_guard<std::mutex> lk(pending_mutex_);
        for (auto& p : pending_) {
            p->done = true;
            p->cv.notify_all();
        }
        pending_.clear();
    }
    state_cv_.notify_all();

    log(LogLevel::Info, "WLFW service stopped");
}

bool WlfwClient::connected() const noexcept {
    return connected_.load(std::memory_order_relaxed);
}

void WlfwClient::set_indication_callback(IndicationCallback cb) {
    std::lock_guard<std::mutex> lk(mutex_);
    indication_cb_ = std::move(cb);
}

void WlfwClient::rx_loop() {
    std::array<std::uint8_t, 0x20000> buf{};
    while (running_) {
        pollfd pfd{fd_, POLLIN, 0};
        const int rc = ::poll(&pfd, 1, 500);
        if (rc < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (rc == 0) continue;
        if (!(pfd.revents & POLLIN)) continue;

        const ssize_t n = ::recv(fd_, buf.data(), buf.size(), 0);
        if (n < static_cast<ssize_t>(sizeof(QmiHeader))) {
            if (!running_) break;
            if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
            continue;
        }
        dispatch_message(std::vector<std::uint8_t>(buf.begin(), buf.begin() + n));
    }

    connected_ = false;
    running_ = false;
    state_cv_.notify_all();
}

void WlfwClient::dispatch_message(const std::vector<std::uint8_t>& packet) {
    if (packet.size() < sizeof(QmiHeader)) return;
    const auto* h = reinterpret_cast<const QmiHeader*>(packet.data());
    const std::uint16_t txn = get_u16_le(reinterpret_cast<const std::uint8_t*>(&h->txn_id));
    const std::uint16_t msg_id = get_u16_le(reinterpret_cast<const std::uint8_t*>(&h->msg_id));
    const std::uint16_t len = get_u16_le(reinterpret_cast<const std::uint8_t*>(&h->msg_len));
    if (packet.size() < sizeof(QmiHeader) + len) return;
    const std::vector<std::uint8_t> payload(packet.begin() + sizeof(QmiHeader),
                                            packet.begin() + sizeof(QmiHeader) + len);

    if (h->type == 2) { // QMI response
        std::lock_guard<std::mutex> lk(pending_mutex_);
        for (auto& p : pending_) {
            if (p->txn == txn && p->msg_id == msg_id && !p->done) {
                p->response = payload;
                p->done = true;
                p->cv.notify_all();
                return;
            }
        }
        return;
    }

    if (h->type == 4) { // QMI indication
        if (msg_id == 0x2b) {
            std::lock_guard<std::mutex> lk(mutex_);
            state_ |= STATE_MSA_READY;
            state_cv_.notify_all();
        } else if (msg_id == 0x37) {
            std::lock_guard<std::mutex> lk(mutex_);
            state_ |= STATE_MEM_READY;
            state_cv_.notify_all();
        } else if (msg_id == 0x28) {
            // wlfw_handle_initiate_cal_download_ind: TLV 0x01 = cal_id (u32).
            // FW is asking us to send back the calibration blob for cal_id;
            // answer on a detached thread so the QRTR RX loop isn't blocked
            // by the (possibly multi-chunk, retrying) 0x27 send.
            std::uint32_t cal_id = 0;
            if (find_tlv_u32(payload, 0x01, cal_id)) {
                std::lock_guard<std::mutex> worker_lk(worker_mutex_);
                if (running_) workers_.emplace_back([this, cal_id] {
                    if (!handle_cal_download_indication(cal_id))
                        log(LogLevel::Warn, "wlfw_send_cal_download_req: cal_id %u failed", cal_id);
                });
            } else {
                log(LogLevel::Warn, "wlfw_handle_initiate_cal_download_ind: fail to decode msg");
            }
        } else if (msg_id == 0x2a) {
            // wlfw_handle_initiate_cal_update_ind: TLV 0x01 cal_id, 0x02 total_size.
            // FW is pushing a fresh calibration blob for us to persist; pull it
            // back via WLFW_CAL_UPDATE_REQ (0x29) on a detached thread so the
            // QRTR RX loop isn't blocked by the multi-segment exchange.
            std::uint32_t cal_id = 0, total_size = 0;
            if (find_tlv_u32(payload, 0x01, cal_id) && find_tlv_u32(payload, 0x02, total_size)) {
                std::lock_guard<std::mutex> worker_lk(worker_mutex_);
                if (running_) workers_.emplace_back([this, cal_id, total_size] {
                    if (!handle_cal_update_indication(cal_id, total_size))
                        log(LogLevel::Warn, "wlfw_send_cal_update_req: cal_id %u failed", cal_id);
                });
            } else {
                log(LogLevel::Warn, "wlfw_handle_initiate_cal_update_ind: fail to decode msg");
            }
        } else if (msg_id == 0x41) {
            if (!handle_qdss_trace_save_indication(payload))
                log(LogLevel::Warn, "wlfw_handle_qdss_trace_save_ind: failed to save trace");
        }

        IndicationCallback cb;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            cb = indication_cb_;
        }
        if (cb) cb(msg_id, payload);
    }
}

bool WlfwClient::send_packet(const std::vector<std::uint8_t>& packet) {
    sockaddr_qrtr peer{};
    peer.sq_family = AF_QIPCRTR;
    peer.sq_node = server_node_;
    peer.sq_port = server_port_;

    std::lock_guard<std::mutex> txlk(tx_mutex_);
    const ssize_t n = ::sendto(fd_, packet.data(), packet.size(), 0,
                               reinterpret_cast<const sockaddr*>(&peer), sizeof(peer));
    return n == static_cast<ssize_t>(packet.size());
}

bool WlfwClient::request(std::uint16_t msg_id, const std::vector<std::uint8_t>& payload,
                         std::vector<std::uint8_t>& response) {
    if (!connected()) return false;
    if (payload.size() > 0xffffu) return false;

    auto pending = std::make_shared<Pending>();
    {
        std::lock_guard<std::mutex> lk(pending_mutex_);
        pending->txn = next_txn_++;
        if (next_txn_ == 0) next_txn_ = 1;
        pending->msg_id = msg_id;
        pending_.push_back(pending);
    }

    std::vector<std::uint8_t> packet(sizeof(QmiHeader) + payload.size(), 0);
    packet[0] = 0; // QMI_REQUEST
    put_u16_le(packet.data() + 1, pending->txn);
    put_u16_le(packet.data() + 3, msg_id);
    put_u16_le(packet.data() + 5, static_cast<std::uint16_t>(payload.size()));
    if (!payload.empty()) std::memcpy(packet.data() + sizeof(QmiHeader), payload.data(), payload.size());

    if (!send_packet(packet)) {
        std::lock_guard<std::mutex> lk(pending_mutex_);
        pending_.erase(std::remove(pending_.begin(), pending_.end(), pending), pending_.end());
        return false;
    }

    std::unique_lock<std::mutex> lk(pending_mutex_);
    const bool done = pending->cv.wait_for(lk, std::chrono::seconds(10), [&] {
        return pending->done || !running_.load();
    });
    if (!done || !pending->done) {
        pending_.erase(std::remove(pending_.begin(), pending_.end(), pending), pending_.end());
        return false;
    }
    response = pending->response;
    pending_.erase(std::remove(pending_.begin(), pending_.end(), pending), pending_.end());
    return true;
}

bool WlfwClient::parse_result(const std::vector<std::uint8_t>& payload,
                              std::uint16_t& result, std::uint16_t& error) {
    std::size_t off = 0;
    result = 0xffff;
    error = 0xffff;
    while (off + 3 <= payload.size()) {
        const std::uint8_t type = payload[off];
        const std::uint16_t len = get_u16_le(payload.data() + off + 1);
        off += 3;
        if (off + len > payload.size()) return false;
        if (type == 0x02 && len >= 4) {
            result = get_u16_le(payload.data() + off);
            error = get_u16_le(payload.data() + off + 2);
            return true;
        }
        off += len;
    }
    return false;
}

bool WlfwClient::send_raw(std::uint16_t msg_id, const void* req, std::size_t req_len,
                          void* rsp, std::size_t rsp_len) {
    const auto* bytes = static_cast<const std::uint8_t*>(req);
    std::vector<std::uint8_t> payload(bytes, bytes + req_len);
    std::vector<std::uint8_t> response;
    if (!request(msg_id, payload, response)) {
        log(LogLevel::Warn, "QMI 0x%04x request failed", msg_id);
        return false;
    }

    std::uint16_t result = 0xffff, error = 0xffff;
    if (parse_result(response, result, error)) {
        log((result == 0 && error == 0) ? LogLevel::Debug : LogLevel::Warn,
            "QMI 0x%04x response result=%u error=%u", msg_id, result, error);
        if (result != 0 || error != 0) return false;
    }

    if (rsp && rsp_len) std::memcpy(rsp, response.data(), std::min(rsp_len, response.size()));
    return true;
}

bool WlfwClient::send_indication_register(std::uint64_t& fw_status) {
    // QMI WLFW IND_REGISTER_REQ (0x20).  Field order and TLV tags follow the
    // real wlfw_ind_register_req_msg_v01 IDL (11 fields, tags 0x10..0x1A):
    //   0x10 fw_ready_enable              (u8)
    //   0x11 initiate_cal_download_enable  (u8)
    //   0x12 msa_ready_enable             (u8)
    //   0x13 pin_connect_result_enable    (u8)
    //   0x14 client_id                    (u32) -- valid=0 in daemon: NOT sent
    //   0x15 request_mem_enable           (u8)
    //   0x16 fw_mem_ready_enable          (u8)
    //   0x17 fw_init_done_enable          (u8)
    //   0x18 rejuvenate_enable            (u32) -- valid=0: NOT sent
    //   0x19 xo_cal_enable                (u8)
    //   0x1A cal_done_enable              (u8)
    // Instance mask from wlfw_send_ind_register_req():
    //   local_70  all-ones  (inst 0,1,2)  -> 0x10..0x13
    //   local_70  = 0x101   (inst 3)      -> 0x10 only
    //   local_60  = 0x1010000 (inst 1,2,3) -> 0x16
    //   uStack_50 = 0x1010000 (inst 0,2)  -> 0x1A

    std::vector<std::uint8_t> req;
    req.reserve(32);

    add_tlv_u8(req, 0x10, 1);                 // fw_ready_enable (always)
    if (instance_id_ != 3) {
        add_tlv_u8(req, 0x11, 1);             // initiate_cal_download_enable
        add_tlv_u8(req, 0x12, 1);             // msa_ready_enable
        add_tlv_u8(req, 0x13, 1);             // pin_connect_result_enable
    }
    if (instance_id_ != 0)
        add_tlv_u8(req, 0x16, 1);             // fw_mem_ready_enable (inst 1,2,3)
    if (instance_id_ == 0 || instance_id_ == 2)
        add_tlv_u8(req, 0x1A, 1);             // cal_done_enable (inst 0,2)

    log(LogLevel::Debug, "WLFW: IND_REGISTER req (%zu bytes): %s",
        req.size(), hex_str(req).c_str());

    std::vector<std::uint8_t> response;
    if (!request(WLFW_IND_REGISTER_REQ, req, response)) {
        log(LogLevel::Warn, "WLFW: IND_REGISTER request failed (timeout or no response)");
        return false;
    }
    log(LogLevel::Debug, "WLFW: IND_REGISTER rsp (%zu bytes): %s",
        response.size(), hex_str(response).c_str());

    std::uint16_t result = 0xffff, error = 0xffff;
    if (!parse_result(response, result, error) || result != 0 || error != 0) {
        log(LogLevel::Warn, "WLFW: IND_REGISTER result=%u error=%u", result, error);
        return false;
    }

    fw_status = 0;
    std::size_t off = 0;
    while (off + 3 <= response.size()) {
        const std::uint8_t type = response[off];
        const std::uint16_t len = get_u16_le(response.data() + off + 1);
        off += 3;
        if (off + len > response.size()) break;
        if (type == 0x10 && len >= 8)
            fw_status = get_u64_le(response.data() + off);
        off += len;
    }
    {
        std::lock_guard<std::mutex> lk(mutex_);
        state_ |= STATE_CONNECTED;
        if (fw_status & (1ull << 1)) state_ |= STATE_FW_READY;
        if (fw_status & (1ull << 2)) state_ |= STATE_MSA_READY;
        if (fw_status & (1ull << 3)) state_ |= STATE_MEM_READY;
        state_cv_.notify_all();
    }
    return true;
}

bool WlfwClient::send_capability_request() {
    std::vector<std::uint8_t> response;
    if (!request(WLFW_CAP_REQ, {}, response)) return false;
    std::uint16_t result = 0xffff, error = 0xffff;
    if (!parse_result(response, result, error) || result != 0 || error != 0) return false;

    WlfwCapability cap{};
    std::size_t off = 0;
    while (off + 3 <= response.size()) {
        const std::uint8_t type = response[off];
        const std::uint16_t len = get_u16_le(response.data() + off + 1);
        off += 3;
        if (off + len > response.size()) break;
        const auto* p = response.data() + off;
        switch (type) {
            case 0x10:
                // wire TLV: chip_id(u32) + chip_family(u32), no leading valid-byte.
                if (len >= 8) {
                    cap.chip_valid = true;
                    cap.chip_id = get_u32_le(p);
                    cap.chip_family = get_u32_le(p + 4);
                }
                break;
            case 0x11:
                // board_id comes as a single byte on the wire (e.g. 0xff), not u32.
                if (len >= 4) { cap.board_valid = true; cap.board_id = get_u32_le(p); }
                else if (len >= 1) { cap.board_valid = true; cap.board_id = p[0]; }
                break;
            case 0x12:
                if (len >= 4) { cap.soc_valid = true; cap.soc_id = get_u32_le(p); }
                break;
            case 0x13:
                if (len >= 4) {
                    cap.fw_version_valid = true;
                    cap.fw_version = get_u32_le(p);
                    if (len > 4) cap.fw_build_timestamp.assign(reinterpret_cast<const char*>(p + 4), len - 4);
                }
                break;
            case 0x14:
                if (len >= 1) {
                    cap.build_id_valid = true;
                    cap.build_id.assign(reinterpret_cast<const char*>(p), len);
                }
                break;
            case 0x15:
                if (len >= 1) { cap.num_macs_valid = true; cap.num_macs = p[0]; }
                break;
            default:
                break;
        }
        off += len;
    }
    capability_ = std::move(cap);
    log(LogLevel::Info, "WLFW cap: chip=0x%x family=0x%x board=0x%x soc=0x%x fw=0x%x ts=%s",
        capability_.chip_id, capability_.chip_family, capability_.board_id, capability_.soc_id,
        capability_.fw_version, capability_.fw_build_timestamp.c_str());
    return true;
}

bool WlfwClient::send_calibration_report() {
    // Reference daemon reports the calibration ids it has already loaded from
    // /data/vendor/wifi/wlfw_cal_NN.bin.  On the wire the QMI array count is a
    // single byte (QMI_DATA_LEN), followed by count * uint32_t cal ids.
    std::vector<std::uint32_t> ids;
    {
        std::lock_guard<std::mutex> lk(cal_mutex_);
        ids = cal_table_.present_ids();
    }

    std::vector<std::uint8_t> payload;
    const std::uint8_t count = static_cast<std::uint8_t>(std::min<std::size_t>(ids.size(), 9));
    payload.reserve(1u + 4u * count);
    payload.push_back(count);
    for (std::size_t i = 0; i < count; ++i) {
        std::uint8_t b[4];
        put_u32_le(b, ids[i]);
        payload.insert(payload.end(), b, b + 4);
    }

    std::vector<std::uint8_t> req;
    add_tlv(req, 0x01, payload.data(), payload.size());

    std::vector<std::uint8_t> response;
    if (!request(WLFW_CAL_REPORT_REQ, req, response)) {
        log(LogLevel::Warn, "WLFW: CAL_REPORT request failed");
        return false;
    }

    std::uint16_t result = 0xffff, error = 0xffff;
    if (!parse_result(response, result, error)) {
        log(LogLevel::Warn, "WLFW: CAL_REPORT response has no QMI result TLV");
        return false;
    }
    if (result != 0 || error != 0) {
        log(LogLevel::Warn, "WLFW: CAL_REPORT result=%u error=%u", result, error);
        return false;
    }

    log(LogLevel::Info, "WLFW: CAL_REPORT accepted (reported %u ids)", count);
    return true;
}

// 2. Добавляем установку MAC-адреса (сообщение 0x33)
// (Не забудь добавить объявление в qmi.hpp)
bool WlfwClient::send_mac_addr(const std::array<std::uint8_t, 6>& mac) {
    std::vector<std::uint8_t> req;
    // Tag 0x01, Len 6, Payload MAC
    add_tlv(req, 0x01, mac.data(), 6);

    std::vector<std::uint8_t> response;
    log(LogLevel::Info, "Provisioning MAC: %02x:%02x:%02x:%02x:%02x:%02x", 
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return request(0x33, req, response);
}

bool WlfwClient::send_bdf_download(std::uint32_t bdf_type, const std::string& name) {
    std::string found;
    const std::string data_string = read_file_name({
        "/firmware/image/" + name,
        "/vendor/firmware/" + name,
        "/vendor/firmware_mnt/image/" + name,
        platform::base_dir() + "/firmware/" + name,
        platform::base_dir() + "/" + name,
    }, &found);
    if (data_string.empty()) {
        log(LogLevel::Warn, "WLFW: BDF file not found: %s", name.c_str());
        return false;
    }

    const auto* data = reinterpret_cast<const std::uint8_t*>(data_string.data());
    const std::size_t total = data_string.size();
    std::size_t offset = 0;
    std::uint32_t seg = 0;

    do {
        const std::size_t chunk = std::min(BDF_CHUNK, total - offset);
        std::vector<std::uint8_t> req;

        // Рабочий wire-формат WLFW BDF_DOWNLOAD_REQ (0x25), сверено с
        // эталонным скриптом, который успешно грузил BDF на этом FW:
        //   0x01 = 1 (u8, обязательный маркер)
        //   0x10 = file_id (u32 LE, всегда 0)
        //   0x11 = total_size (u32 LE)
        //   0x12 = seg_id (u32 LE)
        //   0x13 = [data_len u16 LE][data...]
        //   0x14 = end (u8)
        //   0x15 = bdf_type (u8)
        add_tlv_u8(req, 0x01, 1);
        add_tlv_u32(req, 0x10, 0);                                  // file_id
        add_tlv_u32(req, 0x11, static_cast<std::uint32_t>(total));   // total_size
        add_tlv_u32(req, 0x12, seg);                                 // seg_id

        std::vector<std::uint8_t> data_payload(2 + chunk);
        data_payload[0] = static_cast<std::uint8_t>(chunk & 0xFF);
        data_payload[1] = static_cast<std::uint8_t>((chunk >> 8) & 0xFF);
        std::memcpy(data_payload.data() + 2, data + offset, chunk);
        add_tlv(req, 0x13, data_payload.data(), data_payload.size());

        add_tlv_u8(req, 0x14, (offset + chunk == total) ? 1 : 0);    // end
        add_tlv_u8(req, 0x15, static_cast<std::uint8_t>(bdf_type));   // bdf_type

        std::vector<std::uint8_t> response;
        if (!request(WLFW_BDF_DOWNLOAD_REQ, req, response)) return false;

        std::uint16_t result = 0, error = 0;
        if (!parse_result(response, result, error) || result != 0 || error != 0) {
            log(LogLevel::Error, "BDF Reject: seg=%u, res=%u, err=%u", seg, result, error);
            return false;
        }

        offset += chunk;
        ++seg;
    } while (offset < total);

    log(LogLevel::Info, "WLFW: downloaded %s (%zu bytes, bdf_type=%u)", found.c_str(), total, bdf_type);
    return true;
}

void WlfwClient::reload_calibration_table() {
    std::lock_guard<std::mutex> lk(cal_mutex_);
    cal_table_.load("/data/vendor/wifi");
    cal_table_.load(platform::base_dir());
}

bool WlfwClient::send_cal_chunk(std::uint32_t cal_id, const std::uint8_t* data, std::size_t total_size,
                                 std::size_t len, std::size_t offset, std::uint32_t seg, bool last) {
    // struct wlfw_cal_download_req_msg_v01, mirrors the BDF download layout:
    // TLV 0x10 cal_id, 0x11 total_size, 0x12 seg_id, 0x13 data_len+data, 0x14 end.
    std::vector<std::uint8_t> req;
    add_tlv_u32(req, 0x10, cal_id);
    add_tlv_u32(req, 0x11, static_cast<std::uint32_t>(total_size));
    add_tlv_u32(req, 0x12, seg);

    std::vector<std::uint8_t> data_tlv(4 + len, 0);
    put_u32_le(data_tlv.data(), static_cast<std::uint32_t>(len));
    std::memcpy(data_tlv.data() + 4, data + offset, len);
    add_tlv(req, 0x13, data_tlv.data(), data_tlv.size());
    add_tlv_u8(req, 0x14, last ? 1 : 0);

    // The original retries a chunk up to 4 times on QMI_ERR_FW_BUSY, waiting
    // 500ms, 1000ms, 1500ms, 2000ms between attempts.
    for (int attempt = 1; attempt <= 4; ++attempt) {
        std::vector<std::uint8_t> response;
        if (!request(WLFW_CAL_DOWNLOAD_REQ, req, response)) return false;
        std::uint16_t result = 0xffff, error = 0xffff;
        parse_result(response, result, error);
        if (result == 0 && error == 0) return true;
        if (error != QMI_ERR_FW_BUSY || attempt == 4) {
            log(LogLevel::Warn, "wlfw_send_cal_download_req: result %u, error %u", result, error);
            return false;
        }
        log(LogLevel::Info, "wlfw_send_cal_download_req: Failed to download CAL seq#%u, retry#%d",
            seg, attempt);
        std::this_thread::sleep_for(std::chrono::microseconds(500000) * attempt);
    }
    return false;
}

bool WlfwClient::handle_cal_download_indication(std::uint32_t cal_id) {
    std::lock_guard<std::mutex> lk(cal_mutex_);
    log(LogLevel::Debug, "wlfw_send_cal_download_req: cal_id %u", cal_id);
    if (cal_id >= 5) return false;
    const auto& blob = cal_table_.blob(cal_id);
    if (blob.empty()) {
        log(LogLevel::Warn, "wlfw_build_cal_table: not read wlfw_cal_%02u.bin", cal_id);
        return false;
    }

    std::size_t offset = 0;
    std::uint32_t seg = 0;
    const std::size_t total = blob.size();
    do {
        const std::size_t chunk = std::min(BDF_CHUNK, total - offset);
        if (!send_cal_chunk(cal_id, blob.data(), total, chunk, offset, seg, offset + chunk == total))
            return false;
        offset += chunk;
        ++seg;
    } while (offset < total);
    return true;
}

bool WlfwClient::request_cal_update_chunk(std::uint32_t cal_id, std::uint32_t seg,
                                          std::vector<std::uint8_t>& out_chunk, bool& last) {
    // struct wlfw_cal_update_req_msg_v01: TLV 0x10 cal_id, 0x12 seg_id — host
    // only names which segment it wants; FW echoes 0x13 data(len+bytes) and
    // 0x14 end in the response, same wire layout as CAL_DOWNLOAD_REQ reversed.
    std::vector<std::uint8_t> req;
    add_tlv_u32(req, 0x10, cal_id);
    add_tlv_u32(req, 0x12, seg);

    for (int attempt = 1; attempt <= 4; ++attempt) {
        std::vector<std::uint8_t> response;
        if (!request(WLFW_CAL_UPDATE_REQ, req, response)) return false;
        std::uint16_t result = 0xffff, error = 0xffff;
        parse_result(response, result, error);
        if (result != 0 || error != 0) {
            if (error != QMI_ERR_FW_BUSY || attempt == 4) {
                log(LogLevel::Warn, "wlfw_send_cal_update_req: result %u, error %u", result, error);
                return false;
            }
            log(LogLevel::Info, "wlfw_send_cal_update_req: Failed to fetch CAL seq#%u, retry#%d",
                seg, attempt);
            std::this_thread::sleep_for(std::chrono::microseconds(500000) * attempt);
            continue;
        }

        std::vector<std::uint8_t> data_tlv;
        if (!find_tlv_bytes(response, 0x13, data_tlv) || data_tlv.size() < 4) {
            log(LogLevel::Warn, "wlfw_send_cal_update_req: response missing data TLV");
            return false;
        }
        const std::uint32_t data_len = get_u32_le(data_tlv.data());
        if (data_tlv.size() < 4 + data_len) {
            log(LogLevel::Warn, "wlfw_send_cal_update_req: truncated data TLV");
            return false;
        }
        out_chunk.assign(data_tlv.begin() + 4, data_tlv.begin() + 4 + static_cast<long>(data_len));

        std::uint8_t end_flag = 0;
        find_tlv_u8(response, 0x14, end_flag);
        last = end_flag != 0;
        return true;
    }
    return false;
}

bool WlfwClient::handle_cal_update_indication(std::uint32_t cal_id, std::uint32_t total_size) {
    std::lock_guard<std::mutex> lk(cal_mutex_);
    log(LogLevel::Debug, "wlfw_send_cal_update_req: cal_id %u size %u", cal_id, total_size);
    if (cal_id >= 5) return false;

    std::vector<std::uint8_t> blob;
    blob.reserve(total_size);
    std::uint32_t seg = 0;
    bool last = false;
    while (!last) {
        std::vector<std::uint8_t> chunk;
        if (!request_cal_update_chunk(cal_id, seg, chunk, last)) return false;
        blob.insert(blob.end(), chunk.begin(), chunk.end());
        ++seg;
        // Safety valve: FW is expected to set the end flag once total_size is
        // reached, but don't spin forever if it never does.
        if (total_size && blob.size() >= total_size) break;
        if (seg > 0x10000) {
            log(LogLevel::Warn, "wlfw_send_cal_update_req: cal_id %u exceeded segment limit", cal_id);
            return false;
        }
    }

    const std::string preferred = "/data/vendor/wifi/wlfw_cal_0" + std::to_string(cal_id) + ".bin";
    const std::string path = platform::resolve_write(preferred, platform::base_dir());
    std::FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) {
        log(LogLevel::Warn, "wlfw_send_cal_update_req: fopen(%s) failed: %s", path.c_str(), std::strerror(errno));
        return false;
    }
    const std::size_t written = std::fwrite(blob.data(), 1, blob.size(), f);
    std::fclose(f);
    if (written != blob.size()) {
        log(LogLevel::Warn, "wlfw_send_cal_update_req: short write to %s", path.c_str());
        return false;
    }

    log(LogLevel::Info, "WLFW: persisted %zu bytes of calibration data for cal_id %u to %s",
        blob.size(), cal_id, path.c_str());

    // Refresh the in-memory table so a subsequent CAL_DOWNLOAD indication
    // (FW re-requesting its own blob later in the same session) sees it.
    cal_table_.load(platform::base_dir());
    cal_table_.load("/data/vendor/wifi");
    return true;
}

std::array<std::uint8_t, 32> WlfwClient::build_qdss_trace_mode_request(
    std::uint32_t mode, std::uint64_t option, std::uint32_t hw_override) {
    std::array<std::uint8_t, 32> request{};
    request[0] = 1;
    put_u32_le(request.data() + 4, mode);
    put_u64_le(request.data() + 8, 1);
    put_u64_le(request.data() + 16, option);
    put_u32_le(request.data() + 24, 1);
    put_u32_le(request.data() + 28, std::min<std::uint32_t>(hw_override, 2));
    return request;
}

bool WlfwClient::send_qdss_trace_mode(std::uint32_t mode, std::uint64_t option) {
    const std::uint32_t hw = read_hw_override();
    std::vector<std::uint8_t> req;
    add_tlv_u32(req, 0x10, mode);
    {
        std::array<std::uint8_t, 8> b{};
        put_u64_le(b.data(), option);
        add_tlv(req, 0x11, b.data(), b.size());
    }
    add_tlv_u32(req, 0x12, hw);

    std::vector<std::uint8_t> response;
    if (!request(WLFW_QDSS_TRACE_MODE_REQ, req, response)) return false;
    std::uint16_t result = 0xffff, error = 0xffff;
    return parse_result(response, result, error) && result == 0 && error == 0;
}

bool WlfwClient::send_qdss_trace_config(const std::vector<std::uint8_t>& config) {
    if (config.empty()) return false;
    std::size_t offset = 0;
    std::uint32_t seg = 0;
    while (offset < config.size()) {
        const std::size_t chunk = std::min(QDSS_CHUNK, config.size() - offset);
        std::vector<std::uint8_t> req;
        add_tlv_u32(req, 0x10, static_cast<std::uint32_t>(config.size()));
        add_tlv_u32(req, 0x11, seg);
        std::vector<std::uint8_t> data_tlv(4 + chunk, 0);
        put_u32_le(data_tlv.data(), static_cast<std::uint32_t>(chunk));
        std::memcpy(data_tlv.data() + 4, config.data() + offset, chunk);
        add_tlv(req, 0x12, data_tlv.data(), data_tlv.size());
        add_tlv_u8(req, 0x13, offset + chunk == config.size() ? 1 : 0);

        std::vector<std::uint8_t> response;
        if (!request(WLFW_QDSS_TRACE_CONFIG_DOWNLOAD_REQ, req, response)) return false;
        std::uint16_t result = 0xffff, error = 0xffff;
        if (!parse_result(response, result, error) || result != 0 || error != 0) return false;
        offset += chunk;
        ++seg;
    }
    return true;
}


bool WlfwClient::send_mac_address(const std::array<std::uint8_t, 6>& mac) {
    std::array<std::uint8_t, 7> req{};
    req[0] = 1; // valid
    std::copy(mac.begin(), mac.end(), req.begin() + 1);
    std::vector<std::uint8_t> response;
    if (!request(0x33, std::vector<std::uint8_t>(req.begin(), req.end()), response)) return false;
    std::uint16_t result=0xffff,error=0xffff;
    return parse_result(response,result,error) && result==0 && error==0;
}

bool WlfwClient::handle_qdss_trace_save_indication(const std::vector<std::uint8_t>& payload) {
    // WLFW_QDSS_TRACE_SAVE_IND (0x41) contains source, total_size and file_name.
    // Accept the common valid/value TLV encoding and tolerate unwrapped strings.
    std::uint32_t total_size=0; std::string file_name; std::uint32_t source=0;
    std::size_t off=0;
    while(off+3<=payload.size()) {
        const std::uint8_t t=payload[off]; const std::uint16_t len=get_u16_le(payload.data()+off+1); off+=3;
        if(off+len>payload.size()) return false;
        const auto* p=payload.data()+off;
        if((t==0x10 || t==0x01) && len>=5) { source=p[0] ? get_u32_le(p+1) : 0; }
        else if((t==0x11 || t==0x02) && len>=5) { if(p[0]) total_size=get_u32_le(p+1); }
        else if((t==0x12 || t==0x03) && len>=1) { const std::size_t start=(p[0] && len>1)?1:0; file_name.assign(reinterpret_cast<const char*>(p+start), len-start); if(!file_name.empty() && file_name.back()==0) file_name.pop_back(); }
        off+=len;
    }
    if(source!=1 || total_size==0 || file_name.empty()) {
        // Some vendor builds expose a raw fixed record. Look for the first printable
        // NUL-terminated string and a nearby u32 total_size.
        for(std::size_t i=0;i<payload.size();++i) {
            if(payload[i]<0x20 || payload[i]>0x7e) continue;
            std::size_t j=i; while(j<payload.size() && payload[j]>=0x20 && payload[j]<=0x7e) ++j;
            if(j-i>=3){ file_name.assign(reinterpret_cast<const char*>(payload.data()+i),j-i); break; }
        }
        if(total_size==0 && payload.size()>=8) total_size=get_u32_le(payload.data()+4);
    }
    if(file_name.empty() || total_size==0) return false;

    std::vector<std::uint8_t> blob; blob.reserve(total_size);
    std::uint32_t seg=0;
    while(blob.size()<total_size) {
        std::array<std::uint8_t,4> req{}; put_u32_le(req.data(),seg);
        std::vector<std::uint8_t> response;
        if(!request(WLFW_QDSS_TRACE_DATA_REQ, std::vector<std::uint8_t>(req.begin(),req.end()), response)) return false;
        std::uint32_t resp_total=0, resp_seg=0, data_len=0; bool total_valid=false, seg_valid=false, data_valid=false, end=false; std::vector<std::uint8_t> data;
        std::size_t ro=0;
        while(ro+3<=response.size()){
            const auto t=response[ro]; const auto len=get_u16_le(response.data()+ro+1); ro+=3; if(ro+len>response.size()) return false; const auto* p=response.data()+ro;
            if((t==0x10||t==0x01)&&len>=5){total_valid=p[0]!=0; if(total_valid)resp_total=get_u32_le(p+1);}
            else if((t==0x11||t==0x02)&&len>=5){seg_valid=p[0]!=0; if(seg_valid)resp_seg=get_u32_le(p+1);}
            else if((t==0x12||t==0x03)&&len>=5){data_valid=p[0]!=0; if(data_valid){data_len=get_u32_le(p+1); if(5+data_len<=len)data.assign(p+5,p+5+data_len);}}
            else if((t==0x13||t==0x04)&&len>=2){end=p[0]!=0 && p[1]!=0;}
            ro+=len;
        }
        if(!total_valid || !seg_valid || !data_valid || resp_total!=total_size || resp_seg!=seg || data.empty() || data.size()>QDSS_CHUNK || blob.size()+data.size()>total_size) return false;
        blob.insert(blob.end(),data.begin(),data.end()); ++seg; if(seg>0x10000) return false; if(end && blob.size()!=total_size) return false;
    }
    const std::string path=platform::resolve_write("/data/vendor/wifi/"+file_name,platform::base_dir());
    if(!platform::write_file(path,blob,false)) return false;
    log(LogLevel::Info,"WLFW QDSS trace saved: %s (%zu bytes)",path.c_str(),blob.size());
    return true;
}

bool WlfwClient::wait_for_state(std::uint64_t mask, std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lk(mutex_);
    return state_cv_.wait_for(lk, timeout, [&] {
        return (state_ & mask) == mask || !running_.load();
    }) && (state_ & mask) == mask;
}

std::uint64_t WlfwClient::state() const noexcept {
    std::lock_guard<std::mutex> lk(mutex_);
    return state_;
}

bool WlfwClient::refresh_fw_status(std::uint64_t& fw_status) {
    if (!connected()) return false;
    if (!send_indication_register(fw_status)) return false;
    log(LogLevel::Debug, "WLFW: refreshed FW status=0x%016llx%s",
        static_cast<unsigned long long>(fw_status),
        (fw_status & (1ull << 1)) ? " (FW_IS_READY)" : "");
    return true;
}

bool WlfwClient::wait_for_fw_ready(std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (running_.load() && std::chrono::steady_clock::now() < deadline) {
        {
            std::lock_guard<std::mutex> lk(mutex_);
            if (state_ & STATE_FW_READY) return true;
        }

        std::uint64_t fw_status = 0;
        if (!refresh_fw_status(fw_status)) return false;
        if (fw_status & (1ull << 1)) return true;

        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    std::uint64_t final_status = 0;
    if (running_.load() && refresh_fw_status(final_status) && (final_status & (1ull << 1)))
        return true;

    log(LogLevel::Warn, "WLFW: FW_IS_READY was not reported before timeout");
    return false;
}

void CalibrationTable::reset() {
    for (auto& e : entries_) e.clear();
}

bool CalibrationTable::load(const std::string& directory) {
    bool any = false;
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        const std::string path = directory + "/wlfw_cal_" + (i < 10 ? "0" : "") + std::to_string(i) + ".bin";
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            log(LogLevel::Debug, "wlfw_build_cal_table: not read %s", path.c_str());
            continue;
        }
        entries_[i] = std::vector<std::uint8_t>((std::istreambuf_iterator<char>(in)),
                                                 std::istreambuf_iterator<char>());
        if (!entries_[i].empty()) {
            any = true;
            log(LogLevel::Info, "Loaded calibration table %zu: %zu bytes", i, entries_[i].size());
        }
    }
    return any;
}

std::vector<std::uint32_t> CalibrationTable::present_ids() const {
    std::vector<std::uint32_t> ids;
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        if (!entries_[i].empty()) ids.push_back(static_cast<std::uint32_t>(i));
    }
    return ids;
}

const std::vector<std::uint8_t>& CalibrationTable::blob(std::size_t index) const {
    static const std::vector<std::uint8_t> empty;
    return index < entries_.size() ? entries_[index] : empty;
}

} // namespace cnss

namespace cnss {
namespace {
constexpr std::uint32_t DMS_SERVICE = 0x02u;

#pragma pack(push, 1)
struct DmsQmiHeader { std::uint8_t type; std::uint16_t txn_id; std::uint16_t msg_id; std::uint16_t msg_len; };
#pragma pack(pop)

static std::uint16_t rd16(const std::uint8_t* p) { return static_cast<std::uint16_t>(p[0] | (static_cast<std::uint16_t>(p[1]) << 8)); }
}

DmsClient::~DmsClient() { stop(); }

void DmsClient::stop() {
    if (fd_ >= 0) ::close(fd_);
    fd_ = -1; node_ = port_ = 0; txn_ = 1;
}

bool DmsClient::start() {
    if (fd_ >= 0) return true;
    fd_ = ::socket(AF_QIPCRTR, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd_ < 0) { log(LogLevel::Warn, "DMS: AF_QIPCRTR: %s", std::strerror(errno)); return false; }
    sockaddr_qrtr local{}; local.sq_family=AF_QIPCRTR; local.sq_node=0; local.sq_port=0;
    if (::bind(fd_, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) < 0) { stop(); return false; }
    return lookup_service(node_, port_);
}

bool DmsClient::lookup_service(std::uint32_t& node, std::uint32_t& port) {
    sockaddr_qrtr ctrl{}; ctrl.sq_family=AF_QIPCRTR; ctrl.sq_node=QRTR_NODE_BCAST; ctrl.sq_port=QRTR_PORT_CTRL;
    qrtr_ctrl_pkt lookup{}; lookup.cmd=10; lookup.server.service=DMS_SERVICE; lookup.server.instance=QRTR_INSTANCE_ANY;
    if (::sendto(fd_, &lookup, sizeof(lookup), 0, reinterpret_cast<const sockaddr*>(&ctrl), sizeof(ctrl)) < 0) return false;
    std::array<std::uint8_t,512> buf{};
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(10);
    while (std::chrono::steady_clock::now()<deadline) {
        pollfd p{fd_,POLLIN,0}; const auto ms=static_cast<int>(std::clamp<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline-std::chrono::steady_clock::now()).count(),1,300));
        if (::poll(&p,1,ms)<=0) continue;
        const ssize_t n=::recv(fd_,buf.data(),buf.size(),0); if (n<static_cast<ssize_t>(sizeof(qrtr_ctrl_pkt))) continue;
        auto* pkt=reinterpret_cast<const qrtr_ctrl_pkt*>(buf.data());
        if (pkt->cmd==11 && pkt->server.service==DMS_SERVICE) { node=pkt->server.node; port=pkt->server.port; return true; }
    }
    log(LogLevel::Warn,"DMS service 0x%x not found",DMS_SERVICE); return false;
}

bool DmsClient::send_packet(const std::vector<std::uint8_t>& packet) {
    sockaddr_qrtr peer{}; peer.sq_family=AF_QIPCRTR; peer.sq_node=node_; peer.sq_port=port_;
    const ssize_t n=::sendto(fd_,packet.data(),packet.size(),0,reinterpret_cast<const sockaddr*>(&peer),sizeof(peer));
    return n==static_cast<ssize_t>(packet.size());
}

std::uint16_t DmsClient::get_u16_le(const std::uint8_t* p){return rd16(p);} 
std::uint32_t DmsClient::get_u32_le(const std::uint8_t* p){return static_cast<std::uint32_t>(p[0])|static_cast<std::uint32_t>(p[1])<<8|static_cast<std::uint32_t>(p[2])<<16|static_cast<std::uint32_t>(p[3])<<24;}

bool DmsClient::parse_result(const std::vector<std::uint8_t>& payload,std::uint16_t& result,std::uint16_t& error){
    std::size_t off=0; result=error=0xffff;
    while(off+3<=payload.size()){ const auto t=payload[off]; const auto len=rd16(payload.data()+off+1); off+=3; if(off+len>payload.size()) return false; if(t==0x02 && len>=4){result=rd16(payload.data()+off);error=rd16(payload.data()+off+2);return true;} off+=len; }
    return false;
}

bool DmsClient::request(std::uint16_t msg_id,const std::vector<std::uint8_t>& payload,std::vector<std::uint8_t>& response,std::chrono::milliseconds timeout){
    DmsQmiHeader h{}; h.type=0; h.txn_id=txn_++; h.msg_id=msg_id; h.msg_len=static_cast<std::uint16_t>(payload.size());
    std::vector<std::uint8_t> packet(sizeof(h)+payload.size()); std::memcpy(packet.data(),&h,sizeof(h)); if(!payload.empty()) std::memcpy(packet.data()+sizeof(h),payload.data(),payload.size());
    if(!send_packet(packet)) return false;
    std::array<std::uint8_t,65536> buf{}; const auto deadline=std::chrono::steady_clock::now()+timeout;
    while(std::chrono::steady_clock::now()<deadline){ pollfd p{fd_,POLLIN,0}; const int ms=static_cast<int>(std::clamp<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline-std::chrono::steady_clock::now()).count(),1,250)); if(::poll(&p,1,ms)<=0) continue; const ssize_t n=::recv(fd_,buf.data(),buf.size(),0); if(n<(ssize_t)sizeof(DmsQmiHeader)) continue; const auto* rh=reinterpret_cast<const DmsQmiHeader*>(buf.data()); if(rh->type!=2 || rh->txn_id!=h.txn_id || rh->msg_id!=msg_id) continue; if(sizeof(*rh)+rh->msg_len>(size_t)n) continue; response.assign(buf.begin()+sizeof(*rh),buf.begin()+sizeof(*rh)+rh->msg_len); return true; }
    return false;
}

bool DmsClient::get_mac(bool bluetooth,std::array<std::uint8_t,6>& mac){
    if(fd_<0 && !start()) return false;
    // The decompiled DMS client passes a 4-byte selector: 0 for WLAN, 1 for BT.
    std::vector<std::uint8_t> req(4,0); if(bluetooth) req[0]=1;
    std::vector<std::uint8_t> rsp; if(!request(0x5c,req,rsp,std::chrono::seconds(2))) return false;
    std::uint16_t result=0xffff,error=0xffff; if(!parse_result(rsp,result,error) || result!=0 || error!=0) return false;
    // Generated Qualcomm QMI bindings expose the six-byte address as a mandatory
    // 0x01 TLV. Accept 0x10 as well for variants that use that tag.
    std::size_t off=0; while(off+3<=rsp.size()){ const auto t=rsp[off]; const auto len=rd16(rsp.data()+off+1); off+=3; if(off+len>rsp.size()) return false; if((t==0x01 || t==0x10) && len>=6){ std::copy_n(rsp.data()+off,6,mac.begin()); return true; } off+=len; }
    return false;
}

} // namespace cnss
