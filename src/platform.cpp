#include "cnss/platform.hpp"
#include "cnss/logger.hpp"
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace cnss::platform {
namespace fs = std::filesystem;

std::string base_dir() {
    const char* env = std::getenv("CNSS_PLATFORM_DIR");
    return (env && *env) ? env : "/veid/modem/wlan";
}

std::string resolve_read(const std::vector<std::string>& candidates) {
    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::is_regular_file(p, ec)) return p;
    }
    return {};
}

std::string resolve_write(const std::string& preferred, const std::string& fallback_root) {
    std::error_code ec;
    const fs::path pp(preferred);
    if (pp.has_parent_path() && fs::exists(pp.parent_path(), ec) && !ec) return preferred;
    return (fs::path(fallback_root) / pp.filename()).string();
}

bool ensure_parent(const std::string& path) {
    std::error_code ec;
    const fs::path parent = fs::path(path).parent_path();
    if (parent.empty()) return true;
    fs::create_directories(parent, ec);
    if (ec) {
        log(LogLevel::Warn, "create_directories(%s): %s", parent.c_str(), ec.message().c_str());
        return false;
    }
    return true;
}

bool write_file(const std::string& path, const std::vector<std::uint8_t>& data, bool append) {
    if (!ensure_parent(path)) return false;
    std::FILE* f = std::fopen(path.c_str(), append ? "ab" : "wb");
    if (!f) {
        log(LogLevel::Warn, "fopen(%s): %s", path.c_str(), std::strerror(errno));
        return false;
    }
    const std::size_t n = data.empty() ? 0 : std::fwrite(data.data(), 1, data.size(), f);
    const int saved = errno;
    std::fclose(f);
    if (n != data.size()) {
        log(LogLevel::Warn, "short write to %s: wrote=%zu want=%zu errno=%d", path.c_str(), n, data.size(), saved);
        return false;
    }
    return true;
}

bool write_text(const std::string& path, const std::string& value) {
    return write_file(path, std::vector<std::uint8_t>(value.begin(), value.end()), false);
}

std::string read_text_file(const std::string& path) {
    std::ifstream in(path);
    if (!in) return {};
    std::ostringstream ss;
    ss << in.rdbuf();
    std::string out = ss.str();
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r' || out.back() == ' ' || out.back() == '\t')) out.pop_back();
    return out;
}

std::string get_property(const std::string& name, const std::string& fallback) {
    // glibc/Linux target: Android's property_get has no equivalent. Mirror the
    // property namespace into /veid/modem/wlan/properties/<name> and also accept
    // an environment override for bring-up/testing.
    std::string env_name = "CNSS_PROP_";
    for (char c : name) env_name += (c == '.' || c == '-' ? '_' : c);
    if (const char* e = std::getenv(env_name.c_str()); e && *e) return e;
    const std::string v = read_text_file((fs::path(base_dir()) / "properties" / name).string());
    return v.empty() ? fallback : v;
}

bool set_property(const std::string& name, const std::string& value) {
    const std::string path = (fs::path(base_dir()) / "properties" / name).string();
    return write_text(path, value);
}

std::string mac_to_string(const std::array<std::uint8_t, 6>& mac, bool reverse) {
    char out[32]{};
    if (reverse) {
        std::snprintf(out, sizeof(out), "%02x%02x%02x%02x%02x%02x", mac[5],mac[4],mac[3],mac[2],mac[1],mac[0]);
    } else {
        std::snprintf(out, sizeof(out), "%02x%02x%02x%02x%02x%02x", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    }
    return out;
}

} // namespace cnss::platform


namespace cnss::platform {
namespace {
std::string fallback_socket_path() { return (std::filesystem::path(base_dir()) / "sockets" / "wigignpt").string(); }
std::string fallback_tuning_path() { return (std::filesystem::path(base_dir()) / "perftuner" / "state").string(); }

bool connect_unix(const std::string& path, int& fd) {
    fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return false;
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (path.size() >= sizeof(addr.sun_path)) { ::close(fd); fd = -1; return false; }
    std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd); fd = -1; return false;
    }
    return true;
}
}

bool update_sys_param(const std::string& path, const std::string& value) {
    if (path.empty()) return false;
    std::FILE* f = std::fopen(path.c_str(), "w");
    if (f) {
        const int rc = std::fputs(value.c_str(), f);
        const int close_rc = std::fclose(f);
        if (rc >= 0 && close_rc == 0) return true;
    }
    const fs::path pp(path);
    std::string fallback;
    if (pp.is_absolute() && pp.string().rfind("/sys/", 0) == 0)
        fallback = (fs::path(base_dir()) / "sys" / pp.string().substr(5)).string();
    else if (pp.is_absolute() && pp.string().rfind("/proc/", 0) == 0)
        fallback = (fs::path(base_dir()) / "proc" / pp.string().substr(6)).string();
    else
        fallback = (fs::path(base_dir()) / pp.filename()).string();
    if (!ensure_parent(fallback)) return false;
    return write_text(fallback, value);
}

std::string read_sys_param(const std::string& path, const std::string& fallback) {
    const std::string direct = read_text_file(path);
    if (!direct.empty()) return direct;
    const fs::path pp(path);
    if (pp.is_absolute() && pp.string().rfind("/proc/", 0) == 0) {
        const std::string alt = (fs::path(base_dir()) / "proc" / pp.string().substr(6)).string();
        const std::string v = read_text_file(alt);
        if (!v.empty()) return v;
    }
    return fallback;
}

bool npt_available() {
    if (const char* e = std::getenv("CNSS_NPT_SOCKET"); e && *e) {
        int fd = -1;
        const bool ok = connect_unix(e, fd);
        if (fd >= 0) ::close(fd);
        return ok;
    }
    const auto p = fallback_socket_path();
    int fd = -1;
    const bool ok = connect_unix(p, fd);
    if (fd >= 0) ::close(fd);
    return ok;
}

bool npt_command(const std::string& command, std::string* reply) {
    const char* e = std::getenv("CNSS_NPT_SOCKET");
    const std::string path = (e && *e) ? std::string(e) : fallback_socket_path();
    int fd = -1;
    if (connect_unix(path, fd)) {
        const std::string msg = command.back() == '\n' ? command : command + "\n";
        const ssize_t n = ::write(fd, msg.data(), msg.size());
        if (n == static_cast<ssize_t>(msg.size())) {
            if (reply) {
                char buf[1024]{};
                const ssize_t r = ::read(fd, buf, sizeof(buf) - 1);
                if (r > 0) *reply = std::string(buf, static_cast<std::size_t>(r));
            }
            ::close(fd);
            return true;
        }
        ::close(fd);
    }
    const std::string sink = (fs::path(base_dir()) / "npt_commands.log").string();
    std::FILE* f = std::fopen(sink.c_str(), "a");
    if (!f) return false;
    const int rc = std::fprintf(f, "%s", command.c_str());
    const int cc = std::fclose(f);
    if (reply) reply->clear();
    return rc >= 0 && cc == 0;
}

bool set_tuning_parameter(const std::string& name, const std::string& value) {
    std::string command = "perftuner set " + name + " " + value + "\n";
    if (npt_command(command)) return true;
    return write_text((fs::path(fallback_tuning_path()).parent_path() / name).string(), value);
}

bool set_tcp_limit_output_bytes(const std::string& value) {
    if (npt_available()) return set_tuning_parameter("tcp_limit_output_bytes", value);
    return update_sys_param("/proc/sys/net/ipv4/tcp_limit_output_bytes", value);
}

bool apply_rps(const std::string& ifname, const std::vector<std::uint16_t>& masks, std::uint32_t soc_id) {
    if (ifname.empty() || ifname.size() >= 16 || masks.size() > 6) return false;
    bool swap_nibbles = false;
    if (soc_id != 0xffffffffu) {
        const std::uint32_t d = soc_id - 0xf6u;
        const bool supported = (d <= 0x3bu && d < 64u && ((0x800000100000021ULL >> d) & 1ULL)) || soc_id == 0xcfu;
        swap_nibbles = !supported;
    }
    bool any = false;
    for (std::size_t q = 0; q < masks.size(); ++q) {
        std::uint16_t mask = masks[q];
        if (swap_nibbles) mask = static_cast<std::uint16_t>(((mask << 4) | (mask >> 4)) & 0xffu);
        char buf[16]{};
        std::snprintf(buf, sizeof(buf), "%x", static_cast<unsigned>(mask));
        const std::string sys = "/sys/class/net/" + ifname + "/queues/rx-" + std::to_string(q) + "/rps_cpus";
        const fs::path fallback = fs::path(base_dir()) / "sys" / "class" / "net" / ifname / "queues" / ("rx-" + std::to_string(q)) / "rps_cpus";
        if (std::FILE* f = std::fopen(sys.c_str(), "w")) {
            const int rc = std::fputs(buf, f);
            const int cc = std::fclose(f);
            any |= rc >= 0 && cc == 0;
        } else {
            any |= write_text(fallback.string(), buf);
        }
    }
    return any || masks.empty();
}

bool set_core_minfreq(bool enable, bool big_cluster, std::uint32_t duration_ms) {
    const std::string cluster = big_cluster ? "big" : "little";
    if (!enable) {
        return npt_command("perftuner release core_minfreq " + cluster + "\n") ||
               write_text((fs::path(base_dir()) / "perf_lock" / "core_minfreq").string(), "released\n");
    }
    const std::uint32_t value = big_cluster ? 0x40800000u : 0x40800100u;
    std::ostringstream os;
    os << "perftuner acquire core_minfreq 0x" << std::hex << value << " " << std::dec << duration_ms << "\n";
    if (npt_command(os.str())) return true;
    std::ostringstream state;
    state << cluster << " 0x" << std::hex << value << " duration_ms=" << std::dec << duration_ms << "\n";
    return write_text((fs::path(base_dir()) / "perf_lock" / "core_minfreq").string(), state.str());
}

bool pm_vote(std::uint32_t modem_type, const std::string& modem_name) {
    std::ostringstream os;
    os << "type=" << modem_type << "\nname=" << modem_name << "\nconnected=1\n";
    return write_text((fs::path(base_dir()) / "pm" / "vote").string(), os.str());
}

bool pm_release_vote(std::uint32_t modem_type, const std::string& modem_name) {
    // Original pm_deinit(): pm_client_disconnect(handle) + pm_client_unregister(handle)
    // for the modem client that pm_vote()/pm_client_connect() established. There is no
    // real pm_client here (glibc has no such service), so mirror the same fallback file
    // that pm_vote() writes, marking the vote released instead of connected.
    std::ostringstream os;
    os << "type=" << modem_type << "\nname=" << modem_name << "\nconnected=0\n";
    return write_text((fs::path(base_dir()) / "pm" / "vote").string(), os.str());
}

} // namespace cnss::platform
