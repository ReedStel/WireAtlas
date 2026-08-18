#include <cstdint>
#include <functional>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "synthetic_capture.hpp"
#include "wireatlas/byte_cursor.hpp"
#include "wireatlas/packet_decoder.hpp"
#include "wireatlas/pcap_reader.hpp"
#include "wireatlas/report.hpp"

namespace {

using wireatlas::synthetic::Bytes;

void require(const bool condition, const std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}

template <typename Exception, typename Callable>
void require_throws(Callable&& callable, const std::string_view expected) {
    try {
        std::invoke(std::forward<Callable>(callable));
    } catch (const Exception& error) {
        require(std::string_view(error.what()).find(expected) != std::string_view::npos,
                "exception did not contain the expected message");
        return;
    }
    throw std::runtime_error("expected exception was not thrown");
}

wireatlas::Capture parse(const Bytes& bytes) {
    const std::string input_bytes(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    std::istringstream input(input_bytes, std::ios::in | std::ios::binary);
    return wireatlas::read_pcap(input);
}

wireatlas::PacketRecord record(Bytes bytes) {
    wireatlas::PacketRecord result;
    result.index = 1;
    result.timestamp_seconds = 1'700'000'000;
    result.timestamp_fraction = 42;
    result.original_length = wireatlas::synthetic::narrow_u32(bytes.size());
    result.bytes = std::move(bytes);
    return result;
}

void write_le32(Bytes& bytes, const std::size_t offset, const std::uint32_t value) {
    require(offset <= bytes.size() && bytes.size() - offset >= 4, "test mutation is out of range");
    bytes[offset] = static_cast<std::uint8_t>(value & 0xffU);
    bytes[offset + 1] = static_cast<std::uint8_t>((value >> 8U) & 0xffU);
    bytes[offset + 2] = static_cast<std::uint8_t>((value >> 16U) & 0xffU);
    bytes[offset + 3] = static_cast<std::uint8_t>(value >> 24U);
}

void byte_cursor_reads_network_order() {
    const Bytes bytes{0x12, 0x34, 0x56, 0x78, 0x9a};
    wireatlas::ByteCursor cursor(bytes);
    require(cursor.read_u8() == 0x12, "read_u8 failed");
    require(cursor.read_be16() == 0x3456, "read_be16 failed");
    require(cursor.remaining() == 2, "remaining byte count is wrong");
    const auto tail = cursor.read_bytes(2);
    require(tail[0] == 0x78 && tail[1] == 0x9a, "read_bytes failed");
}

void byte_cursor_rejects_truncation() {
    const Bytes bytes{0x12};
    wireatlas::ByteCursor cursor(bytes);
    require_throws<wireatlas::ParseError>([&cursor] { static_cast<void>(cursor.read_be16()); }, "ends before");
}

void reads_little_endian_pcap() {
    const auto capture = parse(wireatlas::synthetic::pcap({wireatlas::synthetic::dns_frame()}));
    require(capture.header.byte_order == wireatlas::ByteOrder::little_endian, "wrong byte order");
    require(capture.packets.size() == 1, "wrong packet count");
    require(capture.packets[0].index == 1, "wrong packet index");
}

void reads_big_endian_pcap() {
    const auto capture = parse(wireatlas::synthetic::pcap(
        {wireatlas::synthetic::tcp_frame()}, wireatlas::ByteOrder::big_endian));
    require(capture.header.byte_order == wireatlas::ByteOrder::big_endian, "wrong byte order");
    require(capture.packets[0].bytes.size() == wireatlas::synthetic::tcp_frame().size(), "wrong packet length");
}

void reads_nanosecond_pcap() {
    const auto capture = parse(wireatlas::synthetic::pcap(
        {wireatlas::synthetic::icmp_frame()},
        wireatlas::ByteOrder::little_endian,
        wireatlas::TimestampResolution::nanoseconds));
    require(capture.header.timestamp_resolution == wireatlas::TimestampResolution::nanoseconds,
            "wrong timestamp resolution");
}

void rejects_bad_magic() {
    auto bytes = wireatlas::synthetic::pcap({});
    bytes[0] = 0;
    require_throws<std::runtime_error>([&bytes] { static_cast<void>(parse(bytes)); }, "magic number");
}

void rejects_short_global_header() {
    const Bytes bytes{0xd4, 0xc3, 0xb2, 0xa1};
    require_throws<std::runtime_error>([&bytes] { static_cast<void>(parse(bytes)); }, "complete classic PCAP");
}

void rejects_bad_version() {
    auto bytes = wireatlas::synthetic::pcap({});
    bytes[4] = 3;
    require_throws<std::runtime_error>([&bytes] { static_cast<void>(parse(bytes)); }, "version");
}

void rejects_zero_snapshot_length() {
    auto bytes = wireatlas::synthetic::pcap({});
    write_le32(bytes, 16, 0);
    require_throws<std::runtime_error>([&bytes] { static_cast<void>(parse(bytes)); }, "snapshot length");
}

void rejects_short_record_header() {
    auto bytes = wireatlas::synthetic::pcap({});
    bytes.push_back(0);
    require_throws<std::runtime_error>([&bytes] { static_cast<void>(parse(bytes)); }, "truncated record header");
}

void rejects_short_record_data() {
    auto bytes = wireatlas::synthetic::pcap({wireatlas::synthetic::icmp_frame()});
    bytes.pop_back();
    require_throws<std::runtime_error>([&bytes] { static_cast<void>(parse(bytes)); }, "packet bytes are truncated");
}

void rejects_bad_timestamp_fraction() {
    auto bytes = wireatlas::synthetic::pcap({wireatlas::synthetic::icmp_frame()});
    write_le32(bytes, 28, 1'000'000);
    require_throws<std::runtime_error>([&bytes] { static_cast<void>(parse(bytes)); }, "timestamp fraction");
}

void rejects_capture_larger_than_original() {
    auto bytes = wireatlas::synthetic::pcap({wireatlas::synthetic::icmp_frame()});
    write_le32(bytes, 36, 1);
    require_throws<std::runtime_error>([&bytes] { static_cast<void>(parse(bytes)); }, "exceeds original length");
}

void decodes_dns_query() {
    const auto packet = wireatlas::decode_packet(record(wireatlas::synthetic::dns_frame()), 1);
    require(!packet.malformed, "DNS frame was marked malformed");
    require(packet.protocol == "DNS", "DNS protocol was not selected");
    require(packet.source == "192.0.2.10", "wrong IPv4 source");
    require(packet.destination_port == 53, "wrong destination port");
    require(packet.dns && packet.dns->query_name == "example.test", "wrong DNS query name");
    require(packet.detail == "query example.test A", "wrong DNS detail");
}

void decodes_tcp_syn() {
    const auto packet = wireatlas::decode_packet(record(wireatlas::synthetic::tcp_frame()), 1);
    require(packet.protocol == "TCP", "TCP protocol was not selected");
    require(packet.source_port == 49152 && packet.destination_port == 443, "wrong TCP ports");
    require(packet.detail.find("SYN") != std::string::npos, "SYN flag missing");
}

void decodes_icmp_echo() {
    const auto packet = wireatlas::decode_packet(record(wireatlas::synthetic::icmp_frame()), 1);
    require(packet.protocol == "ICMP", "ICMP protocol was not selected");
    require(packet.detail == "type 8, code 0", "wrong ICMP fields");
}

void decodes_ipv6_udp() {
    const auto packet = wireatlas::decode_packet(record(wireatlas::synthetic::ipv6_udp_frame()), 1);
    require(packet.protocol == "UDP", "UDP protocol was not selected");
    require(packet.source.find("2001:db8") == 0, "wrong IPv6 source");
    require(packet.destination_port == 123, "wrong IPv6 UDP destination port");
}

void decodes_vlan() {
    const auto packet = wireatlas::decode_packet(record(wireatlas::synthetic::dns_frame(false, true)), 1);
    require(packet.vlan_id == 42, "wrong VLAN ID");
    require(packet.layers.size() == 5 && packet.layers[1] == "VLAN", "VLAN layer missing");
}

void decodes_arp() {
    const auto packet = wireatlas::decode_packet(record(wireatlas::synthetic::arp_frame()), 1);
    require(!packet.malformed && packet.protocol == "ARP", "ARP frame was not decoded");
    require(packet.source == "192.0.2.10" && packet.destination == "192.0.2.1",
            "ARP addresses were not decoded");
}

void rejects_short_arp() {
    const auto packet = wireatlas::decode_packet(
        record(wireatlas::synthetic::ethernet({}, 0x0806)), 1);
    require(packet.malformed && packet.error.find("ARP header") != std::string::npos,
            "truncated ARP frame was accepted");
}

void contains_malformed_packets() {
    const auto packet = wireatlas::decode_packet(record({0, 1, 2}), 1);
    require(packet.malformed, "short Ethernet frame was accepted");
    require(packet.error_offset == 0, "wrong parse error offset");
}

void rejects_dns_pointer_cycles() {
    const auto packet = wireatlas::decode_packet(record(wireatlas::synthetic::dns_frame(true)), 1);
    require(packet.malformed, "DNS pointer cycle was accepted");
    require(packet.error.find("pointer loop") != std::string::npos, "pointer-loop error missing");
}

void contains_invalid_udp_lengths() {
    auto frame = wireatlas::synthetic::dns_frame();
    frame[38] = 0;
    frame[39] = 7;
    const auto packet = wireatlas::decode_packet(record(std::move(frame)), 1);
    require(packet.malformed, "invalid UDP length was accepted");
    require(packet.error.find("UDP length") != std::string::npos, "UDP length error missing");
}

void rejects_unsupported_link_type() {
    const auto packet = wireatlas::decode_packet(record(wireatlas::synthetic::dns_frame()), 101);
    require(packet.malformed, "unsupported link type was accepted");
    require(packet.error.find("unsupported link type") != std::string::npos, "link type error missing");
}

wireatlas::Capture demo_capture() {
    return parse(wireatlas::synthetic::demo_pcap());
}

void filters_protocol_case_insensitively() {
    wireatlas::PacketFilter filter;
    filter.protocol = "dns";
    const auto analysis = wireatlas::analyse_capture(demo_capture(), filter);
    require(analysis.packets.size() == 2, "protocol filter returned wrong count");
    require(analysis.protocol_counts.at("DNS") == 2, "protocol count is wrong");
}

void filters_exact_host() {
    wireatlas::PacketFilter filter;
    filter.host = "192.0.2.10";
    const auto analysis = wireatlas::analyse_capture(demo_capture(), filter);
    require(analysis.packets.size() == 5, "host filter returned wrong count");
}

void limits_matching_packets() {
    wireatlas::PacketFilter filter;
    filter.limit = 2;
    const auto analysis = wireatlas::analyse_capture(demo_capture(), filter);
    require(analysis.packets.size() == 2, "packet limit was not applied");
}

void renders_machine_readable_fields() {
    wireatlas::PacketFilter filter;
    filter.limit = 1;
    const auto analysis = wireatlas::analyse_capture(demo_capture(), filter);
    const auto json = wireatlas::render_json(analysis, true);
    require(json.find("\"packet_count\": 1") != std::string::npos, "JSON packet count missing");
    require(json.find("\"query_name\": \"example.test\"") != std::string::npos, "JSON DNS name missing");
    require(wireatlas::render_table(analysis).find("PROTOCOL") != std::string::npos, "table header missing");
}

struct TestCase {
    const char* name;
    void (*run)();
};

}  // namespace

int main() {
    const std::vector<TestCase> tests{
        {"ByteCursor reads network order", byte_cursor_reads_network_order},
        {"ByteCursor rejects truncation", byte_cursor_rejects_truncation},
        {"reads little-endian PCAP", reads_little_endian_pcap},
        {"reads big-endian PCAP", reads_big_endian_pcap},
        {"reads nanosecond PCAP", reads_nanosecond_pcap},
        {"rejects bad magic", rejects_bad_magic},
        {"rejects short global header", rejects_short_global_header},
        {"rejects unsupported version", rejects_bad_version},
        {"rejects zero snapshot length", rejects_zero_snapshot_length},
        {"rejects short record header", rejects_short_record_header},
        {"rejects short record data", rejects_short_record_data},
        {"rejects bad timestamp fraction", rejects_bad_timestamp_fraction},
        {"rejects capture larger than original", rejects_capture_larger_than_original},
        {"decodes DNS query", decodes_dns_query},
        {"decodes TCP SYN", decodes_tcp_syn},
        {"decodes ICMP echo", decodes_icmp_echo},
        {"decodes IPv6 UDP", decodes_ipv6_udp},
        {"decodes VLAN", decodes_vlan},
        {"decodes ARP", decodes_arp},
        {"rejects short ARP", rejects_short_arp},
        {"contains malformed packets", contains_malformed_packets},
        {"rejects DNS pointer cycles", rejects_dns_pointer_cycles},
        {"contains invalid UDP lengths", contains_invalid_udp_lengths},
        {"rejects unsupported link type", rejects_unsupported_link_type},
        {"filters protocol case-insensitively", filters_protocol_case_insensitively},
        {"filters exact host", filters_exact_host},
        {"limits matching packets", limits_matching_packets},
        {"renders machine-readable fields", renders_machine_readable_fields},
    };

    std::size_t passed = 0;
    for (const auto& test : tests) {
        try {
            test.run();
            ++passed;
            std::cout << "[pass] " << test.name << '\n';
        } catch (const std::exception& error) {
            std::cerr << "[fail] " << test.name << ": " << error.what() << '\n';
        }
    }
    std::cout << passed << '/' << tests.size() << " tests passed\n";
    return passed == tests.size() ? 0 : 1;
}
