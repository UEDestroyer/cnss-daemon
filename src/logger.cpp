#include "cnss/logger.hpp"
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <unistd.h>

namespace cnss {
namespace { std::atomic<int> g_level{3}; }
void set_log_level(int level) noexcept { g_level.store(level < 0 ? 0 : level, std::memory_order_relaxed); }
int log_level() noexcept { return g_level.load(std::memory_order_relaxed); }
void logv(LogLevel level, const char* fmt, va_list ap) noexcept {
    if (static_cast<int>(level) > log_level()) return;
    const char* tag = level == LogLevel::Error ? "E" : level == LogLevel::Warn ? "W" : level == LogLevel::Info ? "I" : "D";
    std::fprintf(stderr, "cnss-daemon[%d] %s: ", static_cast<int>(::getpid()), tag);
    std::vfprintf(stderr, fmt, ap);
    std::fputc('\n', stderr);
    std::fflush(stderr);
}
void log(LogLevel level, const char* fmt, ...) noexcept {
    va_list ap; va_start(ap, fmt); logv(level, fmt, ap); va_end(ap);
}
} // namespace cnss
