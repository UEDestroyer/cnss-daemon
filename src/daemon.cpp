#include "cnss/daemon.hpp"
#include "cnss/logger.hpp"
#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fstream>
#include <array>
#include <iterator>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/nl80211.h>
#include <chrono>
#include <filesystem>
#include <sstream>
#include <iomanip>
#include <thread>
#include <linux/qrtr.h>
#include <sys/socket.h>
#include <net/if.h>

namespace cnss {
namespace {
constexpr std::uint8_t CNSS_GENL_CMD_MSG = 1;
constexpr std::uint16_t CNSS_ATTR_TYPE = 1;
constexpr std::uint16_t CNSS_ATTR_FILE_NAME = 2;
constexpr std::uint16_t CNSS_ATTR_TOTAL_SIZE = 3;
constexpr std::uint16_t CNSS_ATTR_SEG_ID = 4;
constexpr std::uint16_t CNSS_ATTR_END = 5;
constexpr std::uint16_t CNSS_ATTR_DATA_LEN = 6;
constexpr std::uint16_t CNSS_ATTR_DATA = 7;

int attr_len(const nlattr* a) { return static_cast<int>(a->nla_len) - NLA_HDRLEN; }
const void* attr_data(const nlattr* a) { return reinterpret_cast<const std::uint8_t*>(a) + NLA_HDRLEN; }
bool attr_ok(const nlattr* a, int rem) { return rem >= NLA_HDRLEN && a->nla_len >= NLA_HDRLEN && a->nla_len <= rem; }
nlattr* attr_next(nlattr* a, int& rem) { const int step=NLA_ALIGN(a->nla_len); rem-=step; return reinterpret_cast<nlattr*>(reinterpret_cast<std::uint8_t*>(a)+step); }

bool read_attr_u32(const std::uint8_t* data, std::size_t len, std::uint16_t wanted, std::uint32_t& out) {
    int rem = static_cast<int>(len);
    auto* a = reinterpret_cast<const nlattr*>(data);
    while (attr_ok(a, rem)) {
        const int l = attr_len(a);
        if ((a->nla_type & NLA_TYPE_MASK) == wanted && l >= 4) { std::memcpy(&out, attr_data(a), 4); return true; }
        a = reinterpret_cast<nlattr*>(reinterpret_cast<std::uint8_t*>(const_cast<nlattr*>(a)) + NLA_ALIGN(a->nla_len));
        rem -= NLA_ALIGN(a->nla_len);
    }
    return false;
}

bool read_attr_bytes(const std::uint8_t* data, std::size_t len, std::uint16_t wanted, std::vector<std::uint8_t>& out) {
    int rem = static_cast<int>(len);
    auto* a = reinterpret_cast<const nlattr*>(data);
    while (attr_ok(a, rem)) {
        const int l = attr_len(a);
        if ((a->nla_type & NLA_TYPE_MASK) == wanted) { const auto* p = static_cast<const std::uint8_t*>(attr_data(a)); out.assign(p, p + l); return true; }
        const int step = NLA_ALIGN(a->nla_len);
        a = reinterpret_cast<const nlattr*>(reinterpret_cast<const std::uint8_t*>(a) + step);
        rem -= step;
    }
    return false;
}

std::uint32_t parse_u32_env_or_file(const char* env_name, const std::string& file_name, std::uint32_t fallback=0xffffffffu) {
    const char* e = std::getenv(env_name);
    std::string s = e && *e ? std::string(e) : platform::read_text_file((std::filesystem::path(platform::base_dir()) / file_name).string());
    if (s.empty()) return fallback;
    char* end = nullptr; errno = 0; unsigned long v = std::strtoul(s.c_str(), &end, 0);
    if (errno || end == s.c_str()) return fallback;
    return static_cast<std::uint32_t>(v);
}

std::string qmi_result_string(const std::vector<std::uint8_t>& response) {
    if (response.size() < 7) return {};
    std::size_t off = 0;
    while (off + 3 <= response.size()) {
        const std::uint8_t t = response[off];
        const std::uint16_t l = static_cast<std::uint16_t>(response[off+1] | (response[off+2] << 8));
        off += 3;
        if (off + l > response.size()) return {};
        if (t == 0x02 && l >= 4) {
            const std::uint16_t result = static_cast<std::uint16_t>(response[off] | (response[off+1] << 8));
            const std::uint16_t err = static_cast<std::uint16_t>(response[off+2] | (response[off+3] << 8));
            return std::to_string(result) + ":" + std::to_string(err);
        }
        off += l;
    }
    return {};
}

class WlanMsgClient {
public:
    ~WlanMsgClient() { stop(); }
    bool start() {
        if (fd_ >= 0) return true;
        std::uint32_t service = parse_u32_env_or_file("CNSS_WLAN_MSG_SERVICE", "qmi.wlan_msg_service", 0xffffffffu);
        if (service == 0xffffffffu || service == 0u) return false;
        service_ = service;
        fd_ = ::socket(AF_QIPCRTR, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (fd_ < 0) return false;
        sockaddr_qrtr local{}; local.sq_family = AF_QIPCRTR; local.sq_node = 0; local.sq_port = 0;
        if (::bind(fd_, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) < 0) { ::close(fd_); fd_=-1; return false; }
        sockaddr_qrtr ctrl{}; ctrl.sq_family=AF_QIPCRTR; ctrl.sq_node=QRTR_NODE_BCAST; ctrl.sq_port=QRTR_PORT_CTRL;
        qrtr_ctrl_pkt lookup{}; lookup.cmd=10; lookup.server.service=service_; lookup.server.instance=QRTR_INSTANCE_ANY;
        if (::sendto(fd_, &lookup, sizeof(lookup), 0, reinterpret_cast<sockaddr*>(&ctrl), sizeof(ctrl)) < 0) { stop(); return false; }
        std::array<std::uint8_t,512> buf{};
        const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(2);
        while (std::chrono::steady_clock::now()<deadline) {
            pollfd p{fd_,POLLIN,0}; auto remain=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-std::chrono::steady_clock::now()).count();
            if (::poll(&p,1,static_cast<int>(std::clamp<long long>(remain,1,200)))<=0) continue;
            const ssize_t n=::recv(fd_,buf.data(),buf.size(),0); if(n<(ssize_t)sizeof(qrtr_ctrl_pkt)) continue;
            const auto* pkt=reinterpret_cast<const qrtr_ctrl_pkt*>(buf.data());
            if(pkt->cmd==11 && pkt->server.service==service_){node_=pkt->server.node;port_=pkt->server.port;return true;}
        }
        stop(); return false;
    }
    void stop(){if(fd_>=0)::close(fd_);fd_=-1;node_=port_=0;txn_=1;}
    bool send(std::uint16_t msg_id,const std::vector<std::uint8_t>& payload){
        if(!start()) return false;
        struct Header{std::uint8_t type;std::uint16_t txn;std::uint16_t id;std::uint16_t len;} __attribute__((packed));
        Header h{0,txn_++,msg_id,static_cast<std::uint16_t>(payload.size())};
        std::vector<std::uint8_t> pkt(sizeof(h)+payload.size()); std::memcpy(pkt.data(),&h,sizeof(h)); if(!payload.empty()) std::memcpy(pkt.data()+sizeof(h),payload.data(),payload.size());
        sockaddr_qrtr peer{};peer.sq_family=AF_QIPCRTR;peer.sq_node=node_;peer.sq_port=port_;
        if(::sendto(fd_,pkt.data(),pkt.size(),0,reinterpret_cast<sockaddr*>(&peer),sizeof(peer))!=(ssize_t)pkt.size()) return false;
        std::array<std::uint8_t,0x10000> buf{}; const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(3);
        while(std::chrono::steady_clock::now()<deadline){pollfd p{fd_,POLLIN,0}; auto remain=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-std::chrono::steady_clock::now()).count();if(::poll(&p,1,static_cast<int>(std::clamp<long long>(remain,1,250)))<=0)continue;const ssize_t n=::recv(fd_,buf.data(),buf.size(),0);if(n<(ssize_t)sizeof(Header))continue;auto*r=reinterpret_cast<const Header*>(buf.data());if(r->type!=2||r->txn!=h.txn||r->id!=msg_id)continue;if(sizeof(*r)+r->len>(size_t)n)continue;const std::vector<std::uint8_t> rsp(buf.begin()+sizeof(*r),buf.begin()+sizeof(*r)+r->len);const auto rs=qmi_result_string(rsp);if(!rs.empty()){const auto colon=rs.find(':');if(colon!=std::string::npos){return std::stoul(rs.substr(0,colon))==0 && std::stoul(rs.substr(colon+1))==0;}}return true;}
        return false;
    }
private:
    static constexpr std::uint32_t QRTR_INSTANCE_ANY = 0xffffffffu;
    int fd_{-1}; std::uint32_t node_{0},port_{0},service_{0}; std::uint16_t txn_{1};
};

}

Daemon* Daemon::instance_ = nullptr;
Daemon::Daemon(Config config) : config_(std::move(config)) { instance_ = this; platform::set_property("daemon.socket", config_.user_socket); }
void Daemon::signal_handler(int) noexcept { if (instance_) instance_->request_stop(); }
void Daemon::request_stop() noexcept { stop_.store(true, std::memory_order_relaxed); }

bool Daemon::init_netlink() {
    if (!cnss_genl_.open()) return false;
    if (!cnss_genl_.resolve_family("cnss-genl")) {
        log(LogLevel::Warn, "cnss-genl family not found; CNSS platform events disabled");
    } else {
        if (cnss_genl_.resolve_group("cnss-genl", "cnss-genl-grp") && cnss_genl_.group_id())
            cnss_genl_.join_group(cnss_genl_.group_id());
    }

    if (!nl80211_.open()) {
        log(LogLevel::Warn, "nl80211 socket unavailable; continuing without vendor events");
    } else if (!nl80211_.resolve_family("nl80211")) {
        log(LogLevel::Warn, "nl80211 family not found; vendor events disabled");
    } else {
        nl80211_family_ = nl80211_.family_id();
        log(LogLevel::Info, "nl80211 family id=%d", nl80211_family_);
        if (nl80211_.resolve_group("nl80211", "vendor") && nl80211_.group_id()) {
            if (!nl80211_.join_group(nl80211_.group_id())) log(LogLevel::Warn, "failed to join nl80211 vendor group");
        } else {
            log(LogLevel::Warn, "nl80211 vendor multicast group not found");
        }
    }

    if (!wlan_svc_.open() || !wlan_svc_.resolve_family("cld80211")) {
        log(LogLevel::Warn, "cld80211 service family unavailable; WLAN_MSG service indications disabled");
    } else if (wlan_svc_.resolve_group("cld80211", "svc_msgs") && wlan_svc_.group_id()) {
        if (!wlan_svc_.join_group(wlan_svc_.group_id())) log(LogLevel::Warn, "failed to join cld80211 svc_msgs group");
        else log(LogLevel::Info, "cld80211 svc_msgs group joined");
    } else {
        log(LogLevel::Warn, "cld80211 svc_msgs multicast group not found");
    }

    if (!neighbor_watch_.open()) {
        log(LogLevel::Warn, "rtnetlink neighbor monitor unavailable; gateway/neighbor tracking disabled");
    }
    return true;
}

bool Daemon::init_user_socket() {
    // Preserve Android's path when usable; otherwise transparently move the
    // user-space ABI to the requested glibc/Linux fallback hierarchy.
    if (!user_socket_.listen(config_.user_socket)) {
        const std::string fallback = platform::base_dir() + "/sockets/cnss_user_server";
        if (fallback == config_.user_socket || !user_socket_.listen(fallback)) return false;
        config_.user_socket = fallback;
    }
    log(LogLevel::Info, "user control socket: %s", user_socket_.path().c_str());
    return true;
}

void Daemon::provision_dms() {
    DmsClient dms;
    if (!dms.start()) {
        log(LogLevel::Warn, "DMS MAC provisioning unavailable");
        return;
    }

    std::array<std::uint8_t,6> wlan{}, bt{};
    if (dms.get_mac(false,wlan)) {
        const std::string mac=platform::mac_to_string(wlan);
        const std::string dir=platform::base_dir()+"/mac_addr";
        platform::write_text(dir+"/wlan.mac",mac);
        platform::set_property("ro.vendor.ril.oem.wifimac",mac);
        if (wlfw_started_) {
            if (!wlfw_.send_mac_address(wlan)) log(LogLevel::Warn,"Failed to send WLAN MAC address to FW");
        }
        log(LogLevel::Info,"DMS WLAN MAC: %s",mac.c_str());
    } else log(LogLevel::Warn,"Failed to get WLAN MAC address");

    if (dms.get_mac(true,bt)) {
        const std::string mac=platform::mac_to_string(bt,true);
        platform::set_property("ro.vendor.ril.oem.btmac",mac);
        platform::write_text(platform::base_dir()+"/mac_addr/bt.mac",mac);
        log(LogLevel::Info,"DMS BT MAC: %s",mac.c_str());
    } else log(LogLevel::Warn,"Failed to get BT MAC address");
}

bool Daemon::start_wlfw() {
    // Faithful port of the reference wlfw_service_request() state machine
    // (cnss-daemon.c).  fw_status bits returned by IND_REGISTER:
    //   bit 0 = already registered, bit 1 = FW_IS_READY,
    //   bit 2 = MSA_READY,       bit 3 = FW_MEMORY_READY.
    // The per-instance flow differs: only instance 0 downloads BDF/REGDB.
    wlfw_.set_indication_callback([](std::uint16_t msg_id, const std::vector<std::uint8_t>& payload) {
        log(LogLevel::Debug, "WLFW indication 0x%04x payload=%zu", msg_id, payload.size());
    });

    if (!wlfw_.start()) return false;

    constexpr std::uint64_t REGISTERED = 1ull << 0;
    constexpr std::uint64_t FW_READY   = 1ull << 1;
    constexpr std::uint64_t MSA_READY  = 1ull << 2;
    constexpr std::uint64_t MEM_READY  = 1ull << 3;

    // The reference reloads /data/vendor/wifi/wlfw_cal_NN.bin before every
    // IND_REGISTER (all instances).
    wlfw_.reload_calibration_table();

    std::uint64_t status = 0;
    if (!wlfw_.send_indication_register(status)) {
        log(LogLevel::Error, "WLFW: IND_REGISTER failed");
        wlfw_.stop();
        return false;
    }

    const std::uint32_t instance = wlfw_.instance_id();
    log(LogLevel::Info, "WLFW: instance=%u FW status=0x%016llx",
        instance, static_cast<unsigned long long>(status));

    // BDF filename mirrors wlfw_send_bdf_download_req(): bdwlan.b<board_id>,
    // falling back to bdwlan.bin when the board id is unknown (0xff).
    auto main_bdf_name = [this]() -> std::string {
        const auto& cap = wlfw_.capability();
        std::uint32_t board = cap.board_valid ? cap.board_id : 0xffu;
        if (board == 0x5f && platform::get_property("ro.board.platform", "") == "holi")
            board = 0x66;
        if (board == 0xff) return "bdwlan.bin";
        std::ostringstream os;
        os << "bdwlan.b" << std::hex << std::setfill('0')
           << (board < 0x100 ? std::setw(2) : std::setw(3)) << board;
        return os.str();
    };

    auto wait_msa = [&](const char* what) -> bool {
        log(LogLevel::Info, "WLFW: waiting for %s", what);
        if (!wlfw_.wait_for_state(MSA_READY, std::chrono::seconds(60))) {
            log(LogLevel::Error, "WLFW: timed out waiting for %s", what);
            return false;
        }
        return true;
    };
    auto wait_mem = [&](const char* what) -> bool {
        log(LogLevel::Info, "WLFW: waiting for %s", what);
        if (!wlfw_.wait_for_state(MEM_READY, std::chrono::seconds(60))) {
            log(LogLevel::Error, "WLFW: timed out waiting for %s", what);
            return false;
        }
        return true;
    };

    switch (instance) {
    case 0:
        if (status & REGISTERED) {
            if (status & FW_READY) { wlfw_started_ = true; return true; }
            log(LogLevel::Error, "WLFW: FW in bad state 0x%llx",
                static_cast<unsigned long long>(status));
            wlfw_.stop();
            return false;
        }
        if (!(status & MSA_READY) && !wait_msa("MSA_READY indication (0x2b)")) {
            wlfw_.stop();
            return false;
        }
        if (!wlfw_.send_capability_request()) {
            log(LogLevel::Error, "WLFW: capability request failed");
            wlfw_.stop();
            return false;
        }
        // REGDB (type 4), up to 3 attempts, non-fatal in the reference.
        {
            bool regdb_ok = false;
            for (int attempt = 0; attempt < 3 && !regdb_ok; ++attempt)
                regdb_ok = wlfw_.send_bdf_download(4, "regdb.bin");
            if (!regdb_ok)
                log(LogLevel::Info, "WLFW: optional REGDB not downloaded");
        }
        // Main BDF (type 0), up to 3 attempts, fatal in the reference.
        {
            bool bdf_ok = false;
            for (int attempt = 0; attempt < 3 && !bdf_ok; ++attempt) {
                bdf_ok = wlfw_.send_bdf_download(0, main_bdf_name());
                if (!bdf_ok && attempt != 2)
                    std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
            if (!bdf_ok) {
                log(LogLevel::Error, "WLFW: mandatory BDF download failed");
                wlfw_.stop();
                return false;
            }
        }
        if (!wlfw_.send_calibration_report()) {
            log(LogLevel::Error, "WLFW: CAL_REPORT failed");
            wlfw_.stop();
            return false;
        }
        wlfw_started_ = true;
        return true;

    case 1:
        if (!(status & FW_READY)) {
            if (!(status & MEM_READY) && !wait_mem("FW memory ready indication (0x37)")) {
                wlfw_.stop();
                return false;
            }
            if (!wlfw_.send_capability_request()) {
                log(LogLevel::Error, "WLFW: capability request failed");
                wlfw_.stop();
                return false;
            }
            // Reference ignores the CAL_REPORT result on instance 1.
            wlfw_.send_calibration_report();
        } else {
            log(LogLevel::Info, "WLFW: FW is already ready, skip!");
        }
        wlfw_started_ = true;
        return true;

    case 2:
        if ((status & REGISTERED) && (status & FW_READY)) {
            log(LogLevel::Info, "WLFW: FW is already ready, skip!");
            wlfw_started_ = true;
            return true;
        }
        if (!(status & MEM_READY) && !wait_mem("FW memory ready indication (0x37)")) {
            wlfw_.stop();
            return false;
        }
        // Reference ignores both results on instance 2.
        wlfw_.send_capability_request();
        wlfw_.send_calibration_report();
        wlfw_started_ = true;
        return true;

    case 3:
        if (!(status & FW_READY) &&
            !(status & MEM_READY) && !wait_mem("FW memory ready indication (0x37)")) {
            wlfw_.stop();
            return false;
        }
        wlfw_started_ = true;
        return true;

    default:
        log(LogLevel::Error, "WLFW: unexpected instance %u", instance);
        wlfw_.stop();
        return false;
    }
}
void Daemon::handle_user_packet() {
    UserPacket packet;
    if (!user_socket_.recv_packet(packet)) return;
    std::int32_t result = 0;
    switch (packet.command) {
        case 1:
            if (!wlfw_started_ || !wlfw_.send_qdss_trace_mode(1, 0)) result = -ENOSYS;
            break;
        case 2:
            if (packet.payload.size() != 8) { result = -EINVAL; break; }
            { std::uint32_t source=0, option_low=0; std::memcpy(&source,packet.payload.data(),4); std::memcpy(&option_low,packet.payload.data()+4,4);
              if (!wlfw_started_ || !wlfw_.send_qdss_trace_mode(source,option_low)) result=-ENOSYS; }
            break;
        case 3: {
            const std::string path=platform::resolve_read({config_.qdss_cfg,config_.qdss_fallback,platform::base_dir()+"/qdss_trace_config.cfg",platform::base_dir()+"/qdss_trace_config.bin"});
            if(path.empty()){result=-ENOENT;break;} std::ifstream in(path,std::ios::binary); qdss_config_.assign(std::istreambuf_iterator<char>(in),{});
            if (qdss_config_.empty() || !wlfw_started_ || !wlfw_.send_qdss_trace_config(qdss_config_)) result=-ENOSYS;
            break; }
        default: result=-EINVAL; log(LogLevel::Warn,"Unknown user command %u",packet.command); break;
    }
    user_socket_.send_response(packet.command, packet.wire_length, result);
}

void Daemon::handle_cnss_genl_packet(const std::vector<std::uint8_t>& packet) {
    int rem_nl=static_cast<int>(packet.size());
    for(auto* nh=reinterpret_cast<nlmsghdr*>(const_cast<std::uint8_t*>(packet.data())); NLMSG_OK(nh,rem_nl); nh=NLMSG_NEXT(nh,rem_nl)){
        if(nh->nlmsg_type==NLMSG_ERROR) continue;
        if(nh->nlmsg_len<NLMSG_LENGTH(GENL_HDRLEN)) continue;
        auto* gh=reinterpret_cast<genlmsghdr*>(NLMSG_DATA(nh));
        if(gh->cmd!=CNSS_GENL_CMD_MSG) continue;
        const std::size_t off=NLMSG_LENGTH(GENL_HDRLEN); const std::size_t alen=nh->nlmsg_len-off;
        if(alen==0 || off+alen>packet.size()) continue;
        std::vector<std::uint8_t> attrs(packet.begin()+static_cast<long>(off),packet.begin()+static_cast<long>(off+alen));
        std::uint8_t type=0,end=0; std::uint32_t total=0,seg=0,data_len=0; std::string name; std::vector<std::uint8_t> data;
        int rem=static_cast<int>(attrs.size()); auto* a=reinterpret_cast<nlattr*>(attrs.data());
        while(attr_ok(a,rem)){
            const auto t=a->nla_type & NLA_TYPE_MASK; const int l=attr_len(a); const auto* p=static_cast<const std::uint8_t*>(attr_data(a));
            if(t==CNSS_ATTR_TYPE && l>=1) type=p[0];
            else if(t==CNSS_ATTR_FILE_NAME && l>0) {name.assign(reinterpret_cast<const char*>(p),static_cast<std::size_t>(l));if(!name.empty()&&name.back()==0)name.pop_back();}
            else if(t==CNSS_ATTR_TOTAL_SIZE && l>=4)std::memcpy(&total,p,4);
            else if(t==CNSS_ATTR_SEG_ID && l>=4)std::memcpy(&seg,p,4);
            else if(t==CNSS_ATTR_END && l>=1)end=p[0];
            else if(t==CNSS_ATTR_DATA_LEN && l>=4)std::memcpy(&data_len,p,4);
            else if(t==CNSS_ATTR_DATA && l>0) data.assign(p,p+l);
            a=attr_next(a,rem);
        }
        if(type!=1 || data.empty()) continue;
        if(data_len && data_len<data.size()) data.resize(data_len);
        if(cnss_segments_.empty() || seg==0) cnss_segments_.clear();
        cnss_segments_.emplace_back(seg,std::move(data));
        if(end){
            std::sort(cnss_segments_.begin(),cnss_segments_.end(),[](const auto&x,const auto&y){return x.first<y.first;});
            std::vector<std::uint8_t> blob; for(const auto& s:cnss_segments_) blob.insert(blob.end(),s.second.begin(),s.second.end());
            if(total && blob.size()!=total) log(LogLevel::Warn,"CNSS GENL file size mismatch %zu != %u",blob.size(),total);
            if(name.empty()) name="qdss_trace.bin";
            const std::string path=platform::resolve_write("/data/vendor/wifi/"+name,platform::base_dir());
            if(platform::write_file(path,blob,false)) log(LogLevel::Info,"CNSS GENL saved %s (%zu bytes)",path.c_str(),blob.size());
            cnss_segments_.clear();
        }
    }
}

void Daemon::handle_hang_event(const std::vector<std::uint8_t>& vdata) {
    std::uint32_t reason = 0xffffffffu;
    std::vector<std::uint8_t> detail;
    read_attr_u32(vdata.data(), vdata.size(), 1, reason);
    read_attr_bytes(vdata.data(), vdata.size(), 2, detail);
    std::ostringstream txt; txt << "reason=" << reason << "\nlength=" << detail.size() << "\n";
    for (std::size_t i=0;i<detail.size();i+=16) { txt << std::hex; for(std::size_t j=i;j<std::min(i+16,detail.size());++j){ txt << (j==i?"":" ") << (static_cast<unsigned>(detail[j])<16?"0":"") << static_cast<unsigned>(detail[j]); } txt << "\n"; }
    platform::write_file(platform::base_dir()+"/hang_event.bin", detail, false);
    platform::write_text(platform::base_dir()+"/hang_event.txt", txt.str());
    log(LogLevel::Warn, "CNSS hang event: reason=%u detail=%zu", reason, detail.size());
}

void Daemon::handle_iot_event(const std::vector<std::uint8_t>& vdata) {
    std::vector<std::uint8_t> mac;
    if (!read_attr_bytes(vdata.data(), vdata.size(), 3, mac) || mac.size() < 6) {
        // Some kernels place the raw MAC directly in vendor data.
        if (vdata.size() >= 6 && vdata.size() < 32) mac.assign(vdata.begin(), vdata.begin()+6);
        else return;
    }
    std::array<std::uint8_t,6> m{}; std::copy_n(mac.begin(),6,m.begin());
    if (iot_trigger_valid_ && m == iot_trigger_mac_) {
        const auto ifindex = ::if_nametoindex("wlan0");
        if (ifindex && !std::vector<std::array<std::uint8_t,6>>(iot_ap_table_.begin(), iot_ap_table_.begin()+static_cast<std::ptrdiff_t>(iot_ap_count_)).empty()) {
            std::vector<std::array<std::uint8_t,6>> v(iot_ap_table_.begin(), iot_ap_table_.begin()+static_cast<std::ptrdiff_t>(iot_ap_count_));
            nl80211_.send_vendor_command(ifindex, 0x1374u, 0xb5u, v);
            log(LogLevel::Info,"interop AP trigger: sent %zu MACs to driver",v.size());
        }
        return;
    }
    std::size_t existing=iot_ap_count_;
    for(std::size_t i=0;i<iot_ap_count_;++i) if(iot_ap_table_[i]==m){existing=i;break;}
    if(existing<iot_ap_count_) return;
    if(iot_ap_count_<iot_ap_table_.size()) iot_ap_table_[iot_ap_count_++]=m;
    else { std::rotate(iot_ap_table_.begin(), iot_ap_table_.begin()+1, iot_ap_table_.end()); iot_ap_table_.back()=m; }
    save_iot_table();
    log(LogLevel::Info,"interop AP added: %s",platform::mac_to_string(m).c_str());
}

bool Daemon::save_iot_table() {
    std::vector<std::uint8_t> blob(iot_ap_table_.size()*6,0xff);
    for(std::size_t i=0;i<iot_ap_table_.size();++i) std::copy(iot_ap_table_[i].begin(),iot_ap_table_[i].end(),blob.begin()+static_cast<std::ptrdiff_t>(i*6));
    return platform::write_file(platform::base_dir()+"/iotap_ps.bin",blob,false);
}

bool Daemon::load_iot_table() {
    const auto path=platform::resolve_read({"/data/vendor/wifi/iotap_ps.bin",platform::base_dir()+"/iotap_ps.bin"});
    if(path.empty()) return false;
    std::ifstream in(path,std::ios::binary); std::vector<std::uint8_t> blob(std::istreambuf_iterator<char>(in),{});
    if(blob.size()!=iot_ap_table_.size()*6) return false;
    iot_ap_count_=0;
    for(std::size_t i=0;i<iot_ap_table_.size();++i){std::copy_n(blob.begin()+static_cast<std::ptrdiff_t>(i*6),6,iot_ap_table_[i].begin()); bool empty=true; for(auto b:iot_ap_table_[i]) if(b!=0 && b!=0xff) empty=false; if(!empty) ++iot_ap_count_;}
    return true;
}

// Restores the recoverable core of the original cnss_gw_update_loop: drains
// the rtnetlink neighbor socket and persists any newly-reachable entries.
// See NeighborWatch's header comment for what is intentionally not
// reconstructed (route-table tracking, the proprietary downstream vendor
// notification).
void Daemon::handle_neighbor_packet() {
    neighbor_watch_.poll_reachable();
}

void Daemon::handle_nl80211_packet(const std::vector<std::uint8_t>& packet) {
    int rem_nl=static_cast<int>(packet.size());
    for(auto* nh=reinterpret_cast<nlmsghdr*>(const_cast<std::uint8_t*>(packet.data())); NLMSG_OK(nh,rem_nl); nh=NLMSG_NEXT(nh,rem_nl)){
        if(nh->nlmsg_type==NLMSG_ERROR || nh->nlmsg_len<NLMSG_LENGTH(GENL_HDRLEN)) continue;
        const auto* gh=reinterpret_cast<const genlmsghdr*>(NLMSG_DATA(nh)); if(nl80211_family_>=0 && nh->nlmsg_type!=static_cast<unsigned>(nl80211_family_)) continue;
        if(gh->cmd!=NL80211_CMD_VENDOR) continue;
        const auto* base=reinterpret_cast<const std::uint8_t*>(gh)+GENL_HDRLEN; const int rem0=static_cast<int>(nh->nlmsg_len-NLMSG_LENGTH(GENL_HDRLEN)); int rem=rem0;
        std::uint32_t vendor=0,subcmd=0; std::vector<std::uint8_t> vdata;
        for(auto* a=reinterpret_cast<const nlattr*>(base);attr_ok(a,rem);){int l=attr_len(a);const auto* p=static_cast<const std::uint8_t*>(attr_data(a));switch(a->nla_type&NLA_TYPE_MASK){case NL80211_ATTR_VENDOR_ID:if(l>=4)std::memcpy(&vendor,p,4);break;case NL80211_ATTR_VENDOR_SUBCMD:if(l>=4)std::memcpy(&subcmd,p,4);break;case NL80211_ATTR_VENDOR_DATA:if(l>0)vdata.assign(p,p+l);break;default:break;}const int step=NLA_ALIGN(a->nla_len);a=reinterpret_cast<const nlattr*>(reinterpret_cast<const std::uint8_t*>(a)+step);rem-=step;}
        log(LogLevel::Info,"nl80211 vendor event: vendor=0x%x subcmd=0x%x data=%zu",vendor,subcmd,vdata.size());
        if(subcmd==0x9d) handle_hang_event(vdata); else if(subcmd==0xb5) handle_iot_event(vdata);
    }
}

void Daemon::handle_wlan_svc_packet(const std::vector<std::uint8_t>& packet) {
    int rem_nl=static_cast<int>(packet.size());
    for(auto* nh=reinterpret_cast<nlmsghdr*>(const_cast<std::uint8_t*>(packet.data())); NLMSG_OK(nh,rem_nl); nh=NLMSG_NEXT(nh,rem_nl)) {
        if(nh->nlmsg_type==NLMSG_ERROR || nh->nlmsg_len<NLMSG_LENGTH(GENL_HDRLEN)) continue;
        const auto* gh=reinterpret_cast<const genlmsghdr*>(NLMSG_DATA(nh));
        const auto* base=reinterpret_cast<const std::uint8_t*>(gh)+GENL_HDRLEN;
        int rem=static_cast<int>(nh->nlmsg_len-NLMSG_LENGTH(GENL_HDRLEN));
        const nlattr* outer=nullptr;
        for(auto* a=reinterpret_cast<const nlattr*>(base);attr_ok(a,rem);){
            const auto t=(a->nla_type&NLA_TYPE_MASK);
            if(t==2 || t==1){outer=a;break;}
            const int step=NLA_ALIGN(a->nla_len);a=reinterpret_cast<const nlattr*>(reinterpret_cast<const std::uint8_t*>(a)+step);rem-=step;
        }
        if(!outer) continue;
        const auto* ob=static_cast<const std::uint8_t*>(attr_data(outer)); int orem=attr_len(outer);
        const nlattr* data_attr=nullptr;
        for(auto* a=reinterpret_cast<const nlattr*>(ob);attr_ok(a,orem);){
            const auto t=(a->nla_type&NLA_TYPE_MASK);
            if(t==2 || t==1){data_attr=a;break;}
            const int step=NLA_ALIGN(a->nla_len);a=reinterpret_cast<const nlattr*>(reinterpret_cast<const std::uint8_t*>(a)+step);orem-=step;
        }
        if(!data_attr || attr_len(data_attr)<4) continue;
        const auto* p=static_cast<const std::uint8_t*>(attr_data(data_attr)); const std::uint16_t type=static_cast<std::uint16_t>(p[0]|(p[1]<<8)); const std::uint16_t len=static_cast<std::uint16_t>(p[2]|(p[3]<<8));
        if(type!=0x1a || 4u+len>static_cast<std::size_t>(attr_len(data_attr))) continue;
        indications_.dispatch(type,reinterpret_cast<const std::uint8_t*>(p+4),len);
    }
}

void Daemon::handle_netlink_packet(const std::vector<std::uint8_t>& packet) { handle_cnss_genl_packet(packet); }

void Daemon::send_wlan_status_or_version(bool version) {
    WlanMsgClient client;
    if (!client.start()) {
        log(LogLevel::Debug, "WLAN_MSG QMI service not configured/available; state persisted locally");
        return;
    }
    const auto& blob = version ? std::vector<std::uint8_t>(wlan_version_blob_.begin(),wlan_version_blob_.end()) : wlan_status_blob_;
    if (!blob.empty() && !client.send(version ? 0x20 : 0x21, blob)) log(LogLevel::Warn,"WLAN_MSG QMI 0x%02x rejected",version?0x20:0x21);
}

bool Daemon::handle_wlan_dp_message(std::uint16_t type, const std::uint8_t* data, std::size_t len) {
    if(!data) return false;
    auto rd16=[&](std::size_t o)->std::uint16_t { if (o+2>len) return 0; return static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[o]) | static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[o+1])<<8)); };
    auto rd32=[&](std::size_t o)->std::uint32_t {return o+4<=len?static_cast<std::uint32_t>(data[o]|(data[o+1]<<8)|(data[o+2]<<16)|(data[o+3]<<24)):0;};
    if(type==0x109){
        if (len < 8) return false;
        const auto level=rd32(0); const auto flags=rd16(4);
        if(level>3) return false;
        if(!tcp_adv_win_scale_saved_valid_){ tcp_adv_win_scale_saved_=platform::read_sys_param("/proc/sys/net/ipv4/tcp_adv_win_scale", ""); tcp_adv_win_scale_saved_valid_=!tcp_adv_win_scale_saved_.empty(); }
        if(level==2 || level==3){ if(flags&2u) platform::update_sys_param("/proc/sys/net/ipv4/tcp_adv_win_scale","1"); if(flags&1u){ if(platform::npt_available()) platform::set_tuning_parameter("tcp_use_userconfig","1"); else platform::update_sys_param("/proc/sys/net/ipv4/tcp_use_userconfig","1"); if(platform::npt_available()) platform::set_tuning_parameter("tcp_delack_seg","20"); else platform::update_sys_param("/proc/sys/net/ipv4/tcp_delack_seg","20"); } }
        else if(level==1){ if(flags&2u) platform::update_sys_param("/proc/sys/net/ipv4/tcp_adv_win_scale","2"); if(flags&1u){ if(platform::npt_available()) platform::set_tuning_parameter("tcp_use_userconfig","0"); else platform::update_sys_param("/proc/sys/net/ipv4/tcp_use_userconfig","0"); } }
        else if(level==0 && (flags&2u) && tcp_adv_win_scale_saved_valid_) platform::update_sys_param("/proc/sys/net/ipv4/tcp_adv_win_scale",tcp_adv_win_scale_saved_);
        return true;
    }
    if(type==0x10a){
        if (len < 0x1e) return false;
        std::string ifname(reinterpret_cast<const char*>(data),16);
        ifname.erase(std::find(ifname.begin(),ifname.end(),'\0'),ifname.end());
        if (ifname.empty()) return false;
        const std::size_t nq=std::min<std::size_t>(rd32(16),6); std::vector<std::uint16_t> masks; for(std::size_t i=0;i<nq;++i)masks.push_back(rd16(18+i*2));
        const auto soc=parse_u32_env_or_file("CNSS_SOC_ID","soc_id",0xffffffffu); return platform::apply_rps(ifname,masks,soc);
    }
    if(type==0x10b){
        if (len < 4) return false;
        const auto level=rd32(0);
        if (level == 1) return platform::set_tcp_limit_output_bytes("506072");
        if (level == 2 || level == 3) return platform::set_tcp_limit_output_bytes("4048579");
        return false;
    }
    if(type==0x10f){
        if (len != 8 || rd16(0) != 0xbaba) return false;
        const auto cluster=rd16(2); const auto duration=rd32(4);
        if (duration == 0) return platform::set_core_minfreq(false,false,0);
        if (cluster == 0x0f) return platform::set_core_minfreq(true,false,duration);
        if (cluster == 0x00f0) return platform::set_core_minfreq(true,true,duration);
        return false;
    }
    return false;
}

void Daemon::handle_wlan_service_indication(std::uint16_t type, const std::uint8_t* data, std::size_t len) {
    log(LogLevel::Debug,"WLAN_MSG indication 0x%x received, payload=%zu",type,len);
    if(type==0x107){
        if(len!=0x44){log(LogLevel::Warn,"WLAN_MSG version invalid len=%zu",len);return;}
        std::copy_n(data,0x44,wlan_version_blob_.begin()); wlan_version_seen_=true; platform::write_file(platform::base_dir()+"/wlan_version.bin",std::vector<std::uint8_t>(data,data+len),false); send_wlan_status_or_version(true); return;
    }
    if(type==0x106){
        if(len!=0x10c0){log(LogLevel::Warn,"WLAN_MSG status invalid len=%zu",len);return;}
        const auto reset=data[1]; const auto seg=data[2];
        if(reset==0){ for(auto& v:wlan_status_segments_)v.clear(); wlan_status_seen_=false; return; }
        if(seg>=wlan_status_segments_.size()) return;
        wlan_status_segments_[seg].assign(data,data+len); wlan_status_seen_=true;
        wlan_status_blob_.assign(data,data+len);
        platform::write_file(platform::base_dir()+"/wlan_status_last.bin",wlan_status_blob_,false);
        send_wlan_status_or_version(false);
        return;
        return;
    }
    if(type>=0x109 && type<=0x10f){ if(!handle_wlan_dp_message(type,data,len)) log(LogLevel::Warn,"WLAN_MSG DP type 0x%x handling failed",type); }
}

void Daemon::register_indications() {
    indications_.set_initialized(true);
    for(std::uint16_t type=0x106;type<=0x10f;++type)
        indications_.register_handler(type,[this](std::uint16_t t,const std::uint8_t* d,std::size_t l){handle_wlan_service_indication(t,d,l);});
    load_iot_table();
    const auto trigger = platform::read_text_file(platform::base_dir()+"/iotap_trigger.mac");
    if(trigger.size()>=12){ unsigned v[6]{}; if(std::sscanf(trigger.c_str(),"%02x%02x%02x%02x%02x%02x",&v[0],&v[1],&v[2],&v[3],&v[4],&v[5])==6){for(int i=0;i<6;++i)iot_trigger_mac_[i]=static_cast<std::uint8_t>(v[i]);iot_trigger_valid_=true;} }
}

void Daemon::pm_init_fallback() {
    const auto name=platform::get_property("pm.modem.name", "modem"); const auto type=parse_u32_env_or_file("CNSS_PM_MODEM_TYPE","pm/modem_type",0);
    if(platform::pm_vote(type,name)){
        log(LogLevel::Debug,"PM fallback vote established for %s",name.c_str());
        pm_voted_=true; pm_modem_type_=type; pm_modem_name_=name;
    }
}

int Daemon::run() {
    set_log_level(config_.debug_level);
    if (!init_netlink()) return 1;
    if (!init_user_socket()) return 1;
    register_indications();

    log(LogLevel::Info, "Daemon started. Monitoring subsystem power...");

    while (!stop_.load(std::memory_order_relaxed)) {
        // Если модем выключен или сброшен — пытаемся "поймать" его
        if (!wlfw_.connected()) {
            if (start_wlfw()) {
                log(LogLevel::Info, "Successfully re-initialized firmware after power reset.");
            } else {
                // Если не нашли сервис — спим 1 сек и пробуем в следующем цикле
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }

        // Подготавливаем POLL для 5 сокетов (добавляем wlfw_.fd())
        pollfd fds[6]{};
        int nfds = 4;
        fds[0].fd = user_socket_.fd(); fds[0].events = POLLIN;
        fds[1].fd = cnss_genl_.fd();   fds[1].events = POLLIN;
        fds[2].fd = nl80211_.fd();     fds[2].events = POLLIN;
        fds[3].fd = wlan_svc_.fd();    fds[3].events = POLLIN;

        int neighbor_slot = -1;
        if (neighbor_watch_.fd() >= 0) {
            neighbor_slot = nfds;
            fds[nfds].fd = neighbor_watch_.fd();
            fds[nfds].events = POLLIN;
            ++nfds;
        }

        int wlfw_slot = -1;
        // САМОЕ ВАЖНОЕ: Если сокет WLFW открыт, мы ДОЛЖНЫ его поллить.
        // Это и есть наше "голосование" - модем видит активного клиента.
        if (wlfw_.connected() && wlfw_.fd() >= 0) {
            wlfw_slot = nfds;
            fds[nfds].fd = wlfw_.fd();
            fds[nfds].events = POLLIN;
            ++nfds;
        }

        const int rc = ::poll(fds, nfds, 1000); // Тайм-аут 1 сек

        if (rc < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (rc > 0) {
            if (fds[0].revents & POLLIN) handle_user_packet();
            if (fds[1].revents & POLLIN) { std::vector<std::uint8_t> p; if (cnss_genl_.recv(p,0)) handle_cnss_genl_packet(p); }
            if (fds[2].revents & POLLIN) { std::vector<std::uint8_t> p; if (nl80211_.recv(p,0)) handle_nl80211_packet(p); }
            if (fds[3].revents & POLLIN) { std::vector<std::uint8_t> p; if (wlan_svc_.recv(p,0)) handle_wlan_svc_packet(p); }
            if (neighbor_slot >= 0 && (fds[neighbor_slot].revents & POLLIN)) handle_neighbor_packet();

            // Если пришли данные от WLFW (например, индикация 0x45 QDSS)
            if (wlfw_slot >= 0 && (fds[wlfw_slot].revents & POLLIN)) {
                // Простая проверка: если recv вернул 0 или ошибку - значит питание пропало
                if (!wlfw_.connected()) {
                    log(LogLevel::Warn, "WLFW connection lost.");
                }
            }
        }
    }

    cleanup();
    return 0;
}


void Daemon::cleanup(){
    // Mirrors original pm_deinit(): every successful pm_vote() must be matched
    // by a pm_release_vote() on shutdown, or the modem power vote leaks.
    if(pm_voted_){
        if(platform::pm_release_vote(pm_modem_type_,pm_modem_name_)) log(LogLevel::Debug,"PM fallback vote released for %s",pm_modem_name_.c_str());
        pm_voted_=false;
    }
    wlfw_.stop();wlfw_started_=false;user_socket_.close();neighbor_watch_.close();
}
} // namespace cnss
