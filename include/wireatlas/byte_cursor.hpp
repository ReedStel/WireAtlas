#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>

namespace wireatlas {

class ParseError final : public std::runtime_error {
public:
    ParseError(std::size_t offset, std::string message)
        : std::runtime_error(std::move(message)), offset_(offset) {}

    [[nodiscard]] std::size_t offset() const noexcept { return offset_; }

private:
    std::size_t offset_;
};

class ByteCursor {
public:
    explicit ByteCursor(std::span<const std::uint8_t> bytes) : bytes_(bytes) {}

    [[nodiscard]] std::size_t position() const noexcept { return position_; }
    [[nodiscard]] std::size_t remaining() const noexcept { return bytes_.size() - position_; }
    [[nodiscard]] bool empty() const noexcept { return remaining() == 0; }

    std::uint8_t read_u8();
    std::uint16_t read_be16();
    std::uint32_t read_be32();
    std::span<const std::uint8_t> read_bytes(std::size_t count);
    void skip(std::size_t count);

private:
    void require(std::size_t count) const;

    std::span<const std::uint8_t> bytes_;
    std::size_t position_{0};
};

}  // namespace wireatlas
