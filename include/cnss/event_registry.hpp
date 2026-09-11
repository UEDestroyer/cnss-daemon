#pragma once
#include <array>
#include <cstdint>
#include <functional>

namespace cnss {

class IndicationRegistry {
public:
    using Handler = std::function<void(std::uint16_t, const std::uint8_t*, std::size_t)>;

    static constexpr std::size_t kMaxEntries = 10;

    bool register_handler(std::uint16_t type, Handler handler);
    bool unregister_handler(std::uint16_t type);
    bool dispatch(std::uint16_t type, const std::uint8_t* data, std::size_t len) const;
    bool initialized() const noexcept { return initialized_; }
    void set_initialized(bool v) noexcept { initialized_ = v; }

private:
    struct Entry {
        std::uint16_t type{};
        Handler handler{};
        bool used{false};
    };
    std::array<Entry, kMaxEntries> entries_{};
    bool initialized_{false};
};

} // namespace cnss
