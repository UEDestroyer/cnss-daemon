#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace cnss::platform {

std::string base_dir();
std::string resolve_read(const std::vector<std::string>& candidates);
std::string resolve_write(const std::string& preferred, const std::string& fallback_root);
bool ensure_parent(const std::string& path);
bool write_file(const std::string& path, const std::vector<std::uint8_t>& data, bool append = false);
bool write_text(const std::string& path, const std::string& value);
std::string read_text_file(const std::string& path);
std::string get_property(const std::string& name, const std::string& fallback = {});
bool set_property(const std::string& name, const std::string& value);
std::string mac_to_string(const std::array<std::uint8_t, 6>& mac, bool reverse = false);

bool update_sys_param(const std::string& path, const std::string& value);
std::string read_sys_param(const std::string& path, const std::string& fallback = {});
bool npt_available();
bool npt_command(const std::string& command, std::string* reply = nullptr);
bool set_tuning_parameter(const std::string& name, const std::string& value);
bool set_tcp_limit_output_bytes(const std::string& value);
bool apply_rps(const std::string& ifname, const std::vector<std::uint16_t>& masks, std::uint32_t soc_id = 0xffffffffu);
bool set_core_minfreq(bool enable, bool big_cluster, std::uint32_t duration_ms);
bool pm_vote(std::uint32_t modem_type, const std::string& modem_name);
// Mirrors original pm_deinit()/pm_release_vote(): disconnects+unregisters the
// pm client established by pm_vote(). Must be called on every shutdown path
// that followed a successful pm_vote(), or the modem power vote leaks.
bool pm_release_vote(std::uint32_t modem_type, const std::string& modem_name);

} // namespace cnss::platform
