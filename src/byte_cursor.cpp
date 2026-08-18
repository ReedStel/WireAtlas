#include "wireatlas/byte_cursor.hpp"

namespace wireatlas {

void ByteCursor::require(const std::size_t count) const {
    if (count > remaining()) {
        throw ParseError(position_, "packet ends before the requested field");
    }
}

std::uint8_t ByteCursor::read_u8() {
    require(1);
    return bytes_[position_++];
}

std::uint16_t ByteCursor::read_be16() {
    require(2);
    const auto value = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(bytes_[position_]) << 8U) |
        static_cast<std::uint16_t>(bytes_[position_ + 1]));
    position_ += 2;
    return value;
}

std::uint32_t ByteCursor::read_be32() {
    require(4);
    const auto value = (static_cast<std::uint32_t>(bytes_[position_]) << 24U) |
                       (static_cast<std::uint32_t>(bytes_[position_ + 1]) << 16U) |
                       (static_cast<std::uint32_t>(bytes_[position_ + 2]) << 8U) |
                       static_cast<std::uint32_t>(bytes_[position_ + 3]);
    position_ += 4;
    return value;
}

std::span<const std::uint8_t> ByteCursor::read_bytes(const std::size_t count) {
    require(count);
    const auto result = bytes_.subspan(position_, count);
    position_ += count;
    return result;
}

void ByteCursor::skip(const std::size_t count) {
    require(count);
    position_ += count;
}

}  // namespace wireatlas
