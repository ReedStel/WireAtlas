#include "wireatlas/pcap_reader.hpp"

#include <array>
#include <fstream>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>

namespace wireatlas {
namespace {

constexpr std::size_t global_header_size = 24;
constexpr std::size_t record_header_size = 16;

std::uint16_t decode_u16(const std::span<const std::uint8_t> bytes, const ByteOrder order) {
    if (order == ByteOrder::little_endian) {
        return static_cast<std::uint16_t>(bytes[0]) |
               static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[1]) << 8U);
    }
    return static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[0]) << 8U) |
           static_cast<std::uint16_t>(bytes[1]);
}

std::uint32_t decode_u32(const std::span<const std::uint8_t> bytes, const ByteOrder order) {
    if (order == ByteOrder::little_endian) {
        return static_cast<std::uint32_t>(bytes[0]) |
               (static_cast<std::uint32_t>(bytes[1]) << 8U) |
               (static_cast<std::uint32_t>(bytes[2]) << 16U) |
               (static_cast<std::uint32_t>(bytes[3]) << 24U);
    }
    return (static_cast<std::uint32_t>(bytes[0]) << 24U) |
           (static_cast<std::uint32_t>(bytes[1]) << 16U) |
           (static_cast<std::uint32_t>(bytes[2]) << 8U) |
           static_cast<std::uint32_t>(bytes[3]);
}

std::span<const std::uint8_t> slice(
    const std::span<const std::uint8_t> bytes,
    const std::size_t offset,
    const std::size_t count) {
    return bytes.subspan(offset, count);
}

std::string packet_error(const std::size_t index, const std::string& message) {
    std::ostringstream output;
    output << "invalid PCAP record " << index << ": " << message;
    return output.str();
}

}  // namespace

Capture read_pcap(std::istream& input) {
    std::array<std::uint8_t, global_header_size> global{};
    input.read(reinterpret_cast<char*>(global.data()), static_cast<std::streamsize>(global.size()));
    if (input.gcount() != static_cast<std::streamsize>(global.size())) {
        throw std::runtime_error("input is not a complete classic PCAP file");
    }

    PcapHeader header;
    const std::array<std::uint8_t, 4> magic{global[0], global[1], global[2], global[3]};
    if (magic == std::array<std::uint8_t, 4>{0xd4, 0xc3, 0xb2, 0xa1}) {
        header.byte_order = ByteOrder::little_endian;
        header.timestamp_resolution = TimestampResolution::microseconds;
    } else if (magic == std::array<std::uint8_t, 4>{0xa1, 0xb2, 0xc3, 0xd4}) {
        header.byte_order = ByteOrder::big_endian;
        header.timestamp_resolution = TimestampResolution::microseconds;
    } else if (magic == std::array<std::uint8_t, 4>{0x4d, 0x3c, 0xb2, 0xa1}) {
        header.byte_order = ByteOrder::little_endian;
        header.timestamp_resolution = TimestampResolution::nanoseconds;
    } else if (magic == std::array<std::uint8_t, 4>{0xa1, 0xb2, 0x3c, 0x4d}) {
        header.byte_order = ByteOrder::big_endian;
        header.timestamp_resolution = TimestampResolution::nanoseconds;
    } else {
        throw std::runtime_error("unsupported capture format: expected a classic PCAP magic number");
    }

    const auto bytes = std::span<const std::uint8_t>(global);
    header.version_major = decode_u16(slice(bytes, 4, 2), header.byte_order);
    header.version_minor = decode_u16(slice(bytes, 6, 2), header.byte_order);
    header.snap_length = decode_u32(slice(bytes, 16, 4), header.byte_order);
    header.link_type = decode_u32(slice(bytes, 20, 4), header.byte_order);

    if (header.version_major != 2 || header.version_minor != 4) {
        throw std::runtime_error("unsupported PCAP version: WireAtlas accepts version 2.4");
    }
    if (header.snap_length == 0 || header.snap_length > maximum_packet_size) {
        throw std::runtime_error("PCAP snapshot length is outside the safe 1–16777216 byte range");
    }

    Capture capture{header, {}};
    std::uint64_t total_captured_bytes = 0;
    std::array<std::uint8_t, record_header_size> record_header{};
    while (true) {
        input.read(reinterpret_cast<char*>(record_header.data()), static_cast<std::streamsize>(record_header.size()));
        const auto header_bytes_read = input.gcount();
        if (header_bytes_read == 0 && input.eof()) break;
        if (header_bytes_read != static_cast<std::streamsize>(record_header.size())) {
            throw std::runtime_error(packet_error(capture.packets.size() + 1, "truncated record header"));
        }
        if (capture.packets.size() >= maximum_packet_count) {
            throw std::runtime_error("capture exceeds the one-million-packet safety limit");
        }

        const auto record_bytes = std::span<const std::uint8_t>(record_header);
        const auto seconds = decode_u32(slice(record_bytes, 0, 4), header.byte_order);
        const auto fraction = decode_u32(slice(record_bytes, 4, 4), header.byte_order);
        const auto captured_length = decode_u32(slice(record_bytes, 8, 4), header.byte_order);
        const auto original_length = decode_u32(slice(record_bytes, 12, 4), header.byte_order);
        const auto fraction_limit = header.timestamp_resolution == TimestampResolution::microseconds
                                        ? 1'000'000U
                                        : 1'000'000'000U;

        if (fraction >= fraction_limit) {
            throw std::runtime_error(packet_error(capture.packets.size() + 1, "timestamp fraction is out of range"));
        }
        if (captured_length > header.snap_length || captured_length > maximum_packet_size) {
            throw std::runtime_error(packet_error(capture.packets.size() + 1, "captured length exceeds the declared safe limit"));
        }
        if (captured_length > original_length) {
            throw std::runtime_error(packet_error(capture.packets.size() + 1, "captured length exceeds original length"));
        }
        if (captured_length > maximum_capture_bytes - total_captured_bytes) {
            throw std::runtime_error("capture exceeds the 512 MiB decoded-data safety limit");
        }

        PacketRecord record;
        record.index = capture.packets.size() + 1;
        record.timestamp_seconds = seconds;
        record.timestamp_fraction = fraction;
        record.timestamp_resolution = header.timestamp_resolution;
        record.original_length = original_length;
        record.bytes.resize(captured_length);
        if (!record.bytes.empty()) {
            input.read(reinterpret_cast<char*>(record.bytes.data()), static_cast<std::streamsize>(record.bytes.size()));
            if (input.gcount() != static_cast<std::streamsize>(record.bytes.size())) {
                throw std::runtime_error(packet_error(record.index, "packet bytes are truncated"));
            }
        }
        total_captured_bytes += captured_length;
        capture.packets.push_back(std::move(record));
    }

    return capture;
}

Capture read_pcap_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("could not open capture: " + path.string());
    }
    return read_pcap(input);
}

}  // namespace wireatlas
