#include "cnss/event_registry.hpp"
#include "cnss/logger.hpp"

namespace cnss {

bool IndicationRegistry::register_handler(std::uint16_t type, Handler handler) {
    if (!initialized_) {
        log(LogLevel::Warn, "nl_loop_register: loop not initialized");
        return false;
    }
    if (!handler) {
        log(LogLevel::Warn, "nl_loop_register: handler is null");
        return false;
    }
    for (auto& e : entries_) {
        if (e.used && e.type == type) {
            e.handler = std::move(handler);
            return true;
        }
    }
    for (auto& e : entries_) {
        if (!e.used) {
            e.type = type;
            e.handler = std::move(handler);
            e.used = true;
            log(LogLevel::Debug, "Registering ind: 0x%x", type);
            return true;
        }
    }
    log(LogLevel::Error, "nl_loop_register: indication table is full: type=0x%x", type);
    return false;
}

bool IndicationRegistry::unregister_handler(std::uint16_t type) {
    for (auto& e : entries_) {
        if (e.used && e.type == type) {
            e = Entry{};
            log(LogLevel::Debug, "Unregistering ind: 0x%x", type);
            return true;
        }
    }
    log(LogLevel::Warn, "nl_loop_unregister: entry not found: 0x%x", type);
    return false;
}

bool IndicationRegistry::dispatch(std::uint16_t type, const std::uint8_t* data, std::size_t len) const {
    for (const auto& e : entries_) {
        if (e.used && e.type == type) {
            e.handler(type, data, len);
            return true;
        }
    }
    log(LogLevel::Warn, "nl_loop_process_msg_svc: failed to find ind_table for type 0x%x", type);
    return false;
}

} // namespace cnss
