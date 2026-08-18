#include "wireatlas/report.hpp"

#include <algorithm>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

namespace wireatlas {
namespace {

constexpr std::size_t source_width = 22;
constexpr std::size_t destination_width = 22;
constexpr std::size_t protocol_width = 8;
constexpr std::size_t detail_width = 42;

std::string timestamp(const PacketSummary& packet) {
    const auto digits = packet.timestamp_resolution == TimestampResolution::microseconds ? 6 : 9;
    std::ostringstream output;
    output << packet.timestamp_seconds << '.' << std::setw(digits) << std::setfill('0')
           << packet.timestamp_fraction;
    return output.str();
}

std::string fit(std::string_view value, const std::size_t width) {
    if (value.size() <= width) return std::string(value);
    if (width <= 3) return std::string(width, '.');
    return std::string(value.substr(0, width - 3)) + "...";
}

std::string json_escape(std::string_view value) {
    std::ostringstream output;
    for (const char raw_character : value) {
        const auto character = static_cast<unsigned char>(raw_character);
        switch (character) {
            case '"': output << "\\\""; break;
            case '\\': output << "\\\\"; break;
            case '\b': output << "\\b"; break;
            case '\f': output << "\\f"; break;
            case '\n': output << "\\n"; break;
            case '\r': output << "\\r"; break;
            case '\t': output << "\\t"; break;
            default:
                if (character < 0x20U) {
                    output << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                           << static_cast<unsigned int>(character) << std::dec;
                } else {
                    output << static_cast<char>(character);
                }
        }
    }
    return output.str();
}

void json_string(std::ostringstream& output, std::string_view value) {
    output << '"' << json_escape(value) << '"';
}

template <typename Value>
void json_optional_number(std::ostringstream& output, const std::optional<Value>& value) {
    if (value) output << *value;
    else output << "null";
}

std::string byte_order_name(const ByteOrder byte_order) {
    return byte_order == ByteOrder::little_endian ? "little-endian" : "big-endian";
}

std::string resolution_name(const TimestampResolution resolution) {
    return resolution == TimestampResolution::microseconds ? "microseconds" : "nanoseconds";
}

}  // namespace

std::string render_table(const Analysis& analysis) {
    std::ostringstream output;
    output << std::left << std::setw(5) << "#"
           << std::setw(18) << "TIMESTAMP"
           << std::setw(static_cast<int>(source_width + 1)) << "SOURCE"
           << std::setw(static_cast<int>(destination_width + 1)) << "DESTINATION"
           << std::setw(static_cast<int>(protocol_width + 1)) << "PROTOCOL"
           << std::right << std::setw(8) << "BYTES" << "  DETAILS\n";
    output << std::string(5 + 18 + source_width + 1 + destination_width + 1 +
                              protocol_width + 1 + 8 + 2 + detail_width,
                          '-')
           << '\n';

    for (const auto& packet : analysis.packets) {
        auto detail = packet.detail;
        if (packet.malformed && detail.rfind("malformed:", 0) != 0) {
            detail += detail.empty() ? "malformed" : "; malformed";
        }
        output << std::left << std::setw(5) << packet.index
               << std::setw(18) << fit(timestamp(packet), 17)
               << std::setw(static_cast<int>(source_width + 1)) << fit(packet.source, source_width)
               << std::setw(static_cast<int>(destination_width + 1)) << fit(packet.destination, destination_width)
               << std::setw(static_cast<int>(protocol_width + 1)) << fit(packet.protocol, protocol_width)
               << std::right << std::setw(8) << packet.captured_length << "  "
               << fit(detail, detail_width) << '\n';
    }
    if (analysis.packets.empty()) output << "No packets matched the selected filters.\n";
    return output.str();
}

std::string render_summary(const Analysis& analysis) {
    std::ostringstream output;
    output << "Capture summary\n"
           << "  packets:          " << analysis.packets.size() << '\n'
           << "  captured bytes:   " << analysis.captured_bytes << '\n'
           << "  malformed:        " << analysis.malformed_packets << '\n'
           << "  link type:        " << analysis.header.link_type << '\n'
           << "  timestamp units:  " << resolution_name(analysis.header.timestamp_resolution) << '\n'
           << "  protocols:\n";
    if (analysis.protocol_counts.empty()) {
        output << "    (none)\n";
    } else {
        for (const auto& [protocol, count] : analysis.protocol_counts) {
            output << "    " << std::left << std::setw(12) << protocol << count << '\n';
        }
    }
    return output.str();
}

std::string render_json(const Analysis& analysis, const bool include_packets) {
    std::ostringstream output;
    output << "{\n"
           << "  \"format\": \"classic-pcap\",\n"
           << "  \"pcap_version\": \"" << analysis.header.version_major << '.'
           << analysis.header.version_minor << "\",\n"
           << "  \"byte_order\": \"" << byte_order_name(analysis.header.byte_order) << "\",\n"
           << "  \"timestamp_resolution\": \""
           << resolution_name(analysis.header.timestamp_resolution) << "\",\n"
           << "  \"snap_length\": " << analysis.header.snap_length << ",\n"
           << "  \"link_type\": " << analysis.header.link_type << ",\n"
           << "  \"packet_count\": " << analysis.packets.size() << ",\n"
           << "  \"captured_bytes\": " << analysis.captured_bytes << ",\n"
           << "  \"malformed_packets\": " << analysis.malformed_packets << ",\n"
           << "  \"protocols\": {";

    bool first = true;
    for (const auto& [protocol, count] : analysis.protocol_counts) {
        if (!first) output << ',';
        output << "\n    ";
        json_string(output, protocol);
        output << ": " << count;
        first = false;
    }
    if (!analysis.protocol_counts.empty()) output << '\n' << "  ";
    output << '}';

    if (include_packets) {
        output << ",\n  \"packets\": [";
        for (std::size_t index = 0; index < analysis.packets.size(); ++index) {
            const auto& packet = analysis.packets[index];
            output << (index == 0 ? "\n" : ",\n") << "    {\n"
                   << "      \"index\": " << packet.index << ",\n"
                   << "      \"timestamp\": ";
            json_string(output, timestamp(packet));
            output << ",\n      \"captured_length\": " << packet.captured_length
                   << ",\n      \"original_length\": " << packet.original_length
                   << ",\n      \"source\": ";
            json_string(output, packet.source);
            output << ",\n      \"destination\": ";
            json_string(output, packet.destination);
            output << ",\n      \"protocol\": ";
            json_string(output, packet.protocol);
            output << ",\n      \"detail\": ";
            json_string(output, packet.detail);
            output << ",\n      \"source_port\": ";
            json_optional_number(output, packet.source_port);
            output << ",\n      \"destination_port\": ";
            json_optional_number(output, packet.destination_port);
            output << ",\n      \"vlan_id\": ";
            json_optional_number(output, packet.vlan_id);
            output << ",\n      \"malformed\": " << (packet.malformed ? "true" : "false")
                   << ",\n      \"layers\": [";
            for (std::size_t layer = 0; layer < packet.layers.size(); ++layer) {
                if (layer != 0) output << ", ";
                json_string(output, packet.layers[layer]);
            }
            output << ']';
            if (packet.dns) {
                output << ",\n      \"dns\": {\n"
                       << "        \"transaction_id\": " << packet.dns->transaction_id << ",\n"
                       << "        \"response\": " << (packet.dns->response ? "true" : "false") << ",\n"
                       << "        \"question_count\": " << packet.dns->question_count << ",\n"
                       << "        \"answer_count\": " << packet.dns->answer_count << ",\n"
                       << "        \"query_name\": ";
                if (packet.dns->query_name) json_string(output, *packet.dns->query_name);
                else output << "null";
                output << ",\n        \"query_type\": ";
                json_optional_number(output, packet.dns->query_type);
                output << "\n      }";
            }
            if (packet.malformed) {
                output << ",\n      \"error_offset\": ";
                json_optional_number(output, packet.error_offset);
                output << ",\n      \"error\": ";
                json_string(output, packet.error);
            }
            output << "\n    }";
        }
        if (!analysis.packets.empty()) output << '\n' << "  ";
        output << ']';
    }
    output << "\n}\n";
    return output.str();
}

}  // namespace wireatlas
