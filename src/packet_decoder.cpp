#include "wireatlas/packet_decoder.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <iomanip>
#include <set>
#include <sstream>
#include <string>
#include <utility>

#include "wireatlas/byte_cursor.hpp"
#include "wireatlas/pcap_reader.hpp"

namespace wireatlas {
namespace {

using Bytes = std::span<const std::uint8_t>;

std::uint16_t be16(const Bytes bytes, const std::size_t offset, const std::size_t base = 0) {
    if (offset > bytes.size() || bytes.size() - offset < 2) {
        throw ParseError(base + offset, "packet ends inside a 16-bit field");
    }
    return static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[offset]) << 8U) |
           static_cast<std::uint16_t>(bytes[offset + 1]);
}

Bytes checked_slice(
    const Bytes bytes,
    const std::size_t offset,
    const std::size_t count,
    const std::size_t base = 0) {
    if (offset > bytes.size() || count > bytes.size() - offset) {
        throw ParseError(base + offset, "declared protocol length exceeds captured bytes");
    }
    return bytes.subspan(offset, count);
}

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](const unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

std::string format_mac(const Bytes bytes) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (index != 0) output << ':';
        output << std::setw(2) << static_cast<unsigned int>(bytes[index]);
    }
    return output.str();
}

std::string format_ipv4(const Bytes bytes) {
    std::ostringstream output;
    output << static_cast<unsigned int>(bytes[0]) << '.'
           << static_cast<unsigned int>(bytes[1]) << '.'
           << static_cast<unsigned int>(bytes[2]) << '.'
           << static_cast<unsigned int>(bytes[3]);
    return output.str();
}

std::string format_ipv6(const Bytes bytes) {
    std::ostringstream output;
    output << std::hex;
    for (std::size_t index = 0; index < 16; index += 2) {
        if (index != 0) output << ':';
        output << be16(bytes, index);
    }
    return output.str();
}

std::string dns_type_name(const std::uint16_t type) {
    switch (type) {
        case 1: return "A";
        case 2: return "NS";
        case 5: return "CNAME";
        case 6: return "SOA";
        case 12: return "PTR";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 33: return "SRV";
        case 255: return "ANY";
        default: return "TYPE" + std::to_string(type);
    }
}

std::string read_dns_name(
    const Bytes dns,
    std::size_t& offset,
    const std::size_t packet_base) {
    std::string name;
    std::size_t position = offset;
    std::size_t return_offset = offset;
    bool jumped = false;
    std::set<std::size_t> visited;
    std::size_t jump_count = 0;

    while (true) {
        if (position >= dns.size()) {
            throw ParseError(packet_base + position, "DNS name exceeds the message boundary");
        }
        const auto length = dns[position];
        if ((length & 0xc0U) == 0xc0U) {
            if (position + 1 >= dns.size()) {
                throw ParseError(packet_base + position, "DNS compression pointer is truncated");
            }
            const auto pointer = static_cast<std::size_t>(
                (static_cast<std::uint16_t>(length & 0x3fU) << 8U) |
                static_cast<std::uint16_t>(dns[position + 1]));
            if (pointer >= dns.size()) {
                throw ParseError(packet_base + position, "DNS compression pointer is outside the message");
            }
            if (!jumped) return_offset = position + 2;
            if (!visited.insert(pointer).second || ++jump_count > 16) {
                throw ParseError(packet_base + position, "DNS compression pointer loop detected");
            }
            position = pointer;
            jumped = true;
            continue;
        }
        if ((length & 0xc0U) != 0) {
            throw ParseError(packet_base + position, "DNS label uses unsupported reserved bits");
        }
        ++position;
        if (length == 0) {
            offset = jumped ? return_offset : position;
            return name.empty() ? "." : name;
        }
        if (length > 63 || position > dns.size() || length > dns.size() - position) {
            throw ParseError(packet_base + position - 1, "DNS label length is invalid");
        }
        if (!name.empty()) name.push_back('.');
        for (std::size_t index = 0; index < length; ++index) {
            const auto character = dns[position + index];
            name.push_back(character >= 0x21U && character <= 0x7eU
                               ? static_cast<char>(character)
                               : '?');
        }
        if (name.size() > 253) {
            throw ParseError(packet_base + position, "DNS name exceeds 253 characters");
        }
        position += length;
        if (!jumped) return_offset = position;
    }
}

void parse_dns(PacketSummary& summary, Bytes payload, std::size_t packet_base, const bool tcp) {
    if (tcp) {
        const auto declared_length = be16(payload, 0, packet_base);
        payload = checked_slice(payload, 2, declared_length, packet_base);
        packet_base += 2;
    }
    if (payload.size() < 12) {
        throw ParseError(packet_base, "DNS header is truncated");
    }

    DnsInfo dns;
    dns.transaction_id = be16(payload, 0, packet_base);
    const auto flags = be16(payload, 2, packet_base);
    dns.response = (flags & 0x8000U) != 0;
    dns.question_count = be16(payload, 4, packet_base);
    dns.answer_count = be16(payload, 6, packet_base);
    if (dns.question_count > 0) {
        std::size_t offset = 12;
        dns.query_name = read_dns_name(payload, offset, packet_base);
        dns.query_type = be16(payload, offset, packet_base);
        static_cast<void>(be16(payload, offset + 2, packet_base));
    }

    summary.layers.push_back("DNS");
    summary.protocol = "DNS";
    summary.detail = dns.response ? "response" : "query";
    if (dns.query_name) {
        summary.detail += " " + *dns.query_name;
        if (dns.query_type) summary.detail += " " + dns_type_name(*dns.query_type);
    }
    summary.dns = std::move(dns);
}

std::string tcp_flags(const std::uint8_t flags) {
    std::string result;
    const std::array<std::pair<std::uint8_t, const char*>, 6> known{{
        {0x20, "URG"}, {0x10, "ACK"}, {0x08, "PSH"},
        {0x04, "RST"}, {0x02, "SYN"}, {0x01, "FIN"},
    }};
    for (const auto& [mask, name] : known) {
        if ((flags & mask) == 0) continue;
        if (!result.empty()) result.push_back(',');
        result += name;
    }
    return result.empty() ? "none" : result;
}

void parse_tcp(PacketSummary& summary, const Bytes bytes, const std::size_t base) {
    if (bytes.size() < 20) throw ParseError(base, "TCP header is truncated");
    summary.source_port = be16(bytes, 0, base);
    summary.destination_port = be16(bytes, 2, base);
    const auto header_length = static_cast<std::size_t>((bytes[12] >> 4U) * 4U);
    if (header_length < 20 || header_length > bytes.size()) {
        throw ParseError(base + 12, "TCP data offset is invalid");
    }
    summary.layers.push_back("TCP");
    summary.protocol = "TCP";
    summary.detail = std::to_string(*summary.source_port) + " → " +
                     std::to_string(*summary.destination_port) + " [" +
                     tcp_flags(bytes[13]) + "]";
    if (*summary.source_port == 53 || *summary.destination_port == 53) {
        parse_dns(summary, bytes.subspan(header_length), base + header_length, true);
    }
}

void parse_udp(PacketSummary& summary, const Bytes bytes, const std::size_t base) {
    if (bytes.size() < 8) throw ParseError(base, "UDP header is truncated");
    summary.source_port = be16(bytes, 0, base);
    summary.destination_port = be16(bytes, 2, base);
    const auto udp_length = static_cast<std::size_t>(be16(bytes, 4, base));
    if (udp_length < 8 || udp_length > bytes.size()) {
        throw ParseError(base + 4, "UDP length is invalid or truncated");
    }
    summary.layers.push_back("UDP");
    summary.protocol = "UDP";
    summary.detail = std::to_string(*summary.source_port) + " → " +
                     std::to_string(*summary.destination_port);
    if (*summary.source_port == 53 || *summary.destination_port == 53) {
        parse_dns(summary, bytes.subspan(8, udp_length - 8), base + 8, false);
    }
}

void parse_icmp(PacketSummary& summary, const Bytes bytes, const std::size_t base, const bool ipv6) {
    if (bytes.size() < 4) throw ParseError(base, "ICMP header is truncated");
    summary.layers.push_back(ipv6 ? "ICMPv6" : "ICMP");
    summary.protocol = ipv6 ? "ICMPv6" : "ICMP";
    summary.detail = "type " + std::to_string(bytes[0]) + ", code " + std::to_string(bytes[1]);
}

void parse_arp(PacketSummary& summary, const Bytes bytes, const std::size_t base) {
    if (bytes.size() < 8) throw ParseError(base, "ARP header is truncated");
    const auto hardware_type = be16(bytes, 0, base);
    const auto protocol_type = be16(bytes, 2, base);
    const auto hardware_length = static_cast<std::size_t>(bytes[4]);
    const auto protocol_length = static_cast<std::size_t>(bytes[5]);
    const auto operation = be16(bytes, 6, base);
    const auto address_bytes = 2U * (hardware_length + protocol_length);
    static_cast<void>(checked_slice(bytes, 8, address_bytes, base));

    summary.layers.push_back("ARP");
    summary.protocol = "ARP";
    if (hardware_type == 1 && protocol_type == 0x0800U &&
        hardware_length == 6 && protocol_length == 4) {
        const auto sender_offset = 8U + hardware_length;
        const auto target_offset = sender_offset + protocol_length + hardware_length;
        summary.source = format_ipv4(checked_slice(bytes, sender_offset, 4, base));
        summary.destination = format_ipv4(checked_slice(bytes, target_offset, 4, base));
        if (operation == 1) {
            summary.detail = "request: who has " + summary.destination + "? tell " + summary.source;
        } else if (operation == 2) {
            summary.detail = "reply: " + summary.source + " is at sender MAC";
        } else {
            summary.detail = "operation " + std::to_string(operation);
        }
    } else {
        summary.detail = "operation " + std::to_string(operation) + ", hardware " +
                         std::to_string(hardware_type) + ", protocol 0x";
        std::ostringstream protocol;
        protocol << std::hex << std::setw(4) << std::setfill('0') << protocol_type;
        summary.detail += protocol.str();
    }
}

void parse_transport(
    PacketSummary& summary,
    const std::uint8_t protocol,
    const Bytes payload,
    const std::size_t base,
    const bool ipv6) {
    if (protocol == 6) parse_tcp(summary, payload, base);
    else if (protocol == 17) parse_udp(summary, payload, base);
    else if ((!ipv6 && protocol == 1) || (ipv6 && protocol == 58)) parse_icmp(summary, payload, base, ipv6);
    else {
        summary.protocol = ipv6 ? "IPv6" : "IPv4";
        summary.detail = "next header " + std::to_string(protocol);
    }
}

void parse_ipv4(PacketSummary& summary, const Bytes bytes, const std::size_t base) {
    if (bytes.size() < 20) throw ParseError(base, "IPv4 header is truncated");
    const auto version = bytes[0] >> 4U;
    const auto header_length = static_cast<std::size_t>((bytes[0] & 0x0fU) * 4U);
    if (version != 4 || header_length < 20 || header_length > bytes.size()) {
        throw ParseError(base, "IPv4 version or header length is invalid");
    }
    const auto total_length = static_cast<std::size_t>(be16(bytes, 2, base));
    if (total_length < header_length || total_length > bytes.size()) {
        throw ParseError(base + 2, "IPv4 total length is invalid or truncated");
    }
    summary.source = format_ipv4(checked_slice(bytes, 12, 4, base));
    summary.destination = format_ipv4(checked_slice(bytes, 16, 4, base));
    summary.layers.push_back("IPv4");
    summary.protocol = "IPv4";

    const auto fragment = be16(bytes, 6, base);
    if ((fragment & 0x1fffU) != 0) {
        summary.detail = "non-initial fragment";
        return;
    }
    parse_transport(summary, bytes[9], bytes.subspan(header_length, total_length - header_length), base + header_length, false);
}

void parse_ipv6(PacketSummary& summary, const Bytes bytes, const std::size_t base) {
    if (bytes.size() < 40) throw ParseError(base, "IPv6 header is truncated");
    if ((bytes[0] >> 4U) != 6) throw ParseError(base, "IPv6 version field is invalid");
    const auto payload_length = static_cast<std::size_t>(be16(bytes, 4, base));
    if (payload_length > bytes.size() - 40) {
        throw ParseError(base + 4, "IPv6 payload length exceeds captured bytes");
    }
    summary.source = format_ipv6(checked_slice(bytes, 8, 16, base));
    summary.destination = format_ipv6(checked_slice(bytes, 24, 16, base));
    summary.layers.push_back("IPv6");
    summary.protocol = "IPv6";
    parse_transport(summary, bytes[6], bytes.subspan(40, payload_length), base + 40, true);
}

bool matches_filter(const PacketSummary& packet, const PacketFilter& filter) {
    if (filter.protocol && lower(packet.protocol) != lower(*filter.protocol)) return false;
    if (filter.host && packet.source != *filter.host && packet.destination != *filter.host) return false;
    return true;
}

}  // namespace

PacketSummary decode_packet(const PacketRecord& record, const std::uint32_t link_type) {
    PacketSummary summary;
    summary.index = record.index;
    summary.timestamp_seconds = record.timestamp_seconds;
    summary.timestamp_fraction = record.timestamp_fraction;
    summary.timestamp_resolution = record.timestamp_resolution;
    summary.captured_length = static_cast<std::uint32_t>(record.bytes.size());
    summary.original_length = record.original_length;

    try {
        if (link_type != ethernet_link_type) {
            throw ParseError(0, "unsupported link type " + std::to_string(link_type) + "; only Ethernet (DLT_EN10MB) is supported");
        }
        ByteCursor cursor(record.bytes);
        const auto destination_mac = cursor.read_bytes(6);
        const auto source_mac = cursor.read_bytes(6);
        auto ether_type = cursor.read_be16();
        summary.source = format_mac(source_mac);
        summary.destination = format_mac(destination_mac);
        summary.layers.push_back("Ethernet");

        if (ether_type == 0x8100U || ether_type == 0x88a8U) {
            const auto tag = cursor.read_be16();
            summary.vlan_id = static_cast<std::uint16_t>(tag & 0x0fffU);
            ether_type = cursor.read_be16();
            summary.layers.push_back("VLAN");
        }

        const auto payload_base = cursor.position();
        const auto payload = cursor.read_bytes(cursor.remaining());
        if (ether_type == 0x0800U) parse_ipv4(summary, payload, payload_base);
        else if (ether_type == 0x86ddU) parse_ipv6(summary, payload, payload_base);
        else if (ether_type == 0x0806U) parse_arp(summary, payload, payload_base);
        else {
            std::ostringstream detail;
            detail << "EtherType 0x" << std::hex << std::setw(4) << std::setfill('0') << ether_type;
            summary.detail = detail.str();
        }
    } catch (const ParseError& error) {
        summary.malformed = true;
        summary.error_offset = error.offset();
        summary.error = error.what();
        if (summary.detail.empty()) summary.detail = "malformed: " + summary.error;
    }
    return summary;
}

Analysis analyse_capture(const Capture& capture, const PacketFilter& filter) {
    Analysis analysis;
    analysis.header = capture.header;
    for (const auto& record : capture.packets) {
        auto packet = decode_packet(record, capture.header.link_type);
        if (!matches_filter(packet, filter)) continue;
        if (filter.limit != 0 && analysis.packets.size() >= filter.limit) break;
        analysis.captured_bytes += packet.captured_length;
        if (packet.malformed) ++analysis.malformed_packets;
        ++analysis.protocol_counts[packet.protocol];
        analysis.packets.push_back(std::move(packet));
    }
    return analysis;
}

}  // namespace wireatlas
