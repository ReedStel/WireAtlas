#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace wireatlas {

enum class ByteOrder { little_endian, big_endian };
enum class TimestampResolution { microseconds, nanoseconds };

struct PcapHeader {
    std::uint16_t version_major{0};
    std::uint16_t version_minor{0};
    std::uint32_t snap_length{0};
    std::uint32_t link_type{0};
    ByteOrder byte_order{ByteOrder::little_endian};
    TimestampResolution timestamp_resolution{TimestampResolution::microseconds};
};

struct PacketRecord {
    std::size_t index{0};
    std::uint32_t timestamp_seconds{0};
    std::uint32_t timestamp_fraction{0};
    TimestampResolution timestamp_resolution{TimestampResolution::microseconds};
    std::uint32_t original_length{0};
    std::vector<std::uint8_t> bytes;
};

struct Capture {
    PcapHeader header;
    std::vector<PacketRecord> packets;
};

struct DnsInfo {
    std::uint16_t transaction_id{0};
    bool response{false};
    std::uint16_t question_count{0};
    std::uint16_t answer_count{0};
    std::optional<std::string> query_name;
    std::optional<std::uint16_t> query_type;
};

struct PacketSummary {
    std::size_t index{0};
    std::uint32_t timestamp_seconds{0};
    std::uint32_t timestamp_fraction{0};
    TimestampResolution timestamp_resolution{TimestampResolution::microseconds};
    std::uint32_t captured_length{0};
    std::uint32_t original_length{0};
    std::string source{"—"};
    std::string destination{"—"};
    std::string protocol{"Ethernet"};
    std::string detail;
    std::vector<std::string> layers;
    std::optional<std::uint16_t> source_port;
    std::optional<std::uint16_t> destination_port;
    std::optional<std::uint16_t> vlan_id;
    std::optional<DnsInfo> dns;
    bool malformed{false};
    std::optional<std::size_t> error_offset;
    std::string error;
};

struct Analysis {
    PcapHeader header;
    std::vector<PacketSummary> packets;
    std::map<std::string, std::size_t> protocol_counts;
    std::uint64_t captured_bytes{0};
    std::size_t malformed_packets{0};
};

struct PacketFilter {
    std::optional<std::string> protocol;
    std::optional<std::string> host;
    std::size_t limit{0};
};

}  // namespace wireatlas
