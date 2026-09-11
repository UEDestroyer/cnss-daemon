#pragma once
#include <cstdarg>
#include <string>

namespace cnss {

enum class LogLevel : int { Error = 1, Warn = 2, Info = 3, Debug = 4 };

void set_log_level(int level) noexcept;
int log_level() noexcept;
void log(LogLevel level, const char* fmt, ...) noexcept;
void logv(LogLevel level, const char* fmt, va_list ap) noexcept;

} // namespace cnss
