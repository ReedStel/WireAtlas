#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>

#include "wireatlas/model.hpp"

namespace wireatlas::synthetic {

using Bytes = std::vector<std::uint8_t>;

inline std::uint16_t narrow_u16(const std::size_t value) {
    if (value > std::numeric_limits<std::uint16_t>::max()) {
        throw std::length_error("synthetic packet exceeds a 16-bit length field");
    }
    return static_cast<std::uint16_t>(value);
}

inline std::uint32_t narrow_u32(const std::size_t value) {
    if (value > std::numeric_limits<std::uint32_t>::max()) {
        throw std::length_error("synthetic packet exceeds a 32-bit length field");
    }
    return static_cast<std::uint32_t>(value);
}

inline void append_be16(Bytes& bytes, const std::uint16_t value) {
    bytes.push_back(static_cast<std::uint8_t>(value >> 8U));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xffU));
}

inline void append_u16(Bytes& bytes, const std::uint16_t value, const ByteOrder order) {
    if (order == ByteOrder::big_endian) {
        append_be16(bytes, value);
    } else {
        bytes.push_back(static_cast<std::uint8_t>(value & 0xffU));
        bytes.push_back(static_cast<std::uint8_t>(value >> 8U));
    }
}

inline void append_u32(Bytes& bytes, const std::uint32_t value, const ByteOrder order) {
    if (order == ByteOrder::big_endian) {
        bytes.push_back(static_cast<std::uint8_t>(value >> 24U));
        bytes.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
        bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
        bytes.push_back(static_cast<std::uint8_t>(value & 0xffU));
    } else {
        bytes.push_back(static_cast<std::uint8_t>(value & 0xffU));
        bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
        bytes.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
        bytes.push_back(static_cast<std::uint8_t>(value >> 24U));
    }
}

inline Bytes udp(const Bytes& payload, const std::uint16_t source, const std::uint16_t destination) {
    Bytes bytes;
    append_be16(bytes, source);
    append_be16(bytes, destination);
    append_be16(bytes, narrow_u16(8U + payload.size()));
    append_be16(bytes, 0);
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

inline Bytes tcp_syn(const std::uint16_t source, const std::uint16_t destination) {
    Bytes bytes;
    append_be16(bytes, source);
    append_be16(bytes, destination);
    bytes.insert(bytes.end(), {0x01, 0x02, 0x03, 0x04});
    bytes.insert(bytes.end(), {0x00, 0x00, 0x00, 0x00});
    bytes.push_back(0x50);
    bytes.push_back(0x02);
    append_be16(bytes, 64240);
    append_be16(bytes, 0);
    append_be16(bytes, 0);
    return bytes;
}

inline Bytes icmp_echo() {
    return {8, 0, 0, 0, 0x12, 0x34, 0, 1, 'W', 'A'};
}

inline Bytes arp_request() {
    Bytes bytes;
    append_be16(bytes, 1);
    append_be16(bytes, 0x0800);
    bytes.push_back(6);
    bytes.push_back(4);
    append_be16(bytes, 1);
    bytes.insert(bytes.end(), {0x02, 0x00, 0x00, 0x00, 0x00, 0x01});
    bytes.insert(bytes.end(), {192, 0, 2, 10});
    bytes.insert(bytes.end(), {0, 0, 0, 0, 0, 0});
    bytes.insert(bytes.end(), {192, 0, 2, 1});
    return bytes;
}

inline Bytes dns_query(const bool pointer_loop = false) {
    Bytes bytes;
    append_be16(bytes, 0x4a71);
    append_be16(bytes, 0x0100);
    append_be16(bytes, 1);
    append_be16(bytes, 0);
    append_be16(bytes, 0);
    append_be16(bytes, 0);
    if (pointer_loop) {
        bytes.push_back(0xc0);
        bytes.push_back(0x0c);
    } else {
        bytes.push_back(7);
        bytes.insert(bytes.end(), {'e', 'x', 'a', 'm', 'p', 'l', 'e'});
        bytes.push_back(4);
        bytes.insert(bytes.end(), {'t', 'e', 's', 't'});
        bytes.push_back(0);
    }
    append_be16(bytes, 1);
    append_be16(bytes, 1);
    return bytes;
}

inline Bytes ipv4(
    const Bytes& payload,
    const std::uint8_t protocol,
    const std::array<std::uint8_t, 4> source = {192, 0, 2, 10},
    const std::array<std::uint8_t, 4> destination = {198, 51, 100, 53}) {
    Bytes bytes{0x45, 0x00};
    append_be16(bytes, narrow_u16(20U + payload.size()));
    append_be16(bytes, 0x1234);
    append_be16(bytes, 0x4000);
    bytes.push_back(64);
    bytes.push_back(protocol);
    append_be16(bytes, 0);
    bytes.insert(bytes.end(), source.begin(), source.end());
    bytes.insert(bytes.end(), destination.begin(), destination.end());
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

inline Bytes ipv6(const Bytes& payload, const std::uint8_t next_header) {
    Bytes bytes{0x60, 0x00, 0x00, 0x00};
    append_be16(bytes, narrow_u16(payload.size()));
    bytes.push_back(next_header);
    bytes.push_back(64);
    const std::array<std::uint8_t, 16> source{
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    const std::array<std::uint8_t, 16> destination{
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    bytes.insert(bytes.end(), source.begin(), source.end());
    bytes.insert(bytes.end(), destination.begin(), destination.end());
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

inline Bytes ethernet(
    const Bytes& payload,
    const std::uint16_t ether_type,
    const bool vlan = false,
    const std::uint16_t vlan_id = 0) {
    Bytes bytes{
        0x02, 0x00, 0x00, 0x00, 0x00, 0x02,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
    };
    if (vlan) {
        append_be16(bytes, 0x8100);
        append_be16(bytes, static_cast<std::uint16_t>(vlan_id & 0x0fffU));
    }
    append_be16(bytes, ether_type);
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

inline Bytes dns_frame(const bool pointer_loop = false, const bool vlan = false) {
    return ethernet(ipv4(udp(dns_query(pointer_loop), 53000, 53), 17), 0x0800, vlan, 42);
}

inline Bytes tcp_frame() {
    return ethernet(ipv4(tcp_syn(49152, 443), 6), 0x0800);
}

inline Bytes icmp_frame() {
    return ethernet(ipv4(icmp_echo(), 1), 0x0800);
}

inline Bytes arp_frame() {
    return ethernet(arp_request(), 0x0806);
}

inline Bytes ipv6_udp_frame() {
    return ethernet(ipv6(udp({'W', 'A'}, 55000, 123), 17), 0x86dd);
}

inline Bytes pcap(
    const std::vector<Bytes>& packets,
    const ByteOrder order = ByteOrder::little_endian,
    const TimestampResolution resolution = TimestampResolution::microseconds) {
    Bytes bytes;
    if (order == ByteOrder::little_endian && resolution == TimestampResolution::microseconds) {
        bytes.insert(bytes.end(), {0xd4, 0xc3, 0xb2, 0xa1});
    } else if (order == ByteOrder::big_endian && resolution == TimestampResolution::microseconds) {
        bytes.insert(bytes.end(), {0xa1, 0xb2, 0xc3, 0xd4});
    } else if (order == ByteOrder::little_endian) {
        bytes.insert(bytes.end(), {0x4d, 0x3c, 0xb2, 0xa1});
    } else {
        bytes.insert(bytes.end(), {0xa1, 0xb2, 0x3c, 0x4d});
    }
    append_u16(bytes, 2, order);
    append_u16(bytes, 4, order);
    append_u32(bytes, 0, order);
    append_u32(bytes, 0, order);
    append_u32(bytes, 65535, order);
    append_u32(bytes, 1, order);

    for (std::size_t index = 0; index < packets.size(); ++index) {
        append_u32(bytes, static_cast<std::uint32_t>(1'700'000'000U + index), order);
        append_u32(bytes, static_cast<std::uint32_t>((index + 1U) * 1'000U), order);
        append_u32(bytes, narrow_u32(packets[index].size()), order);
        append_u32(bytes, narrow_u32(packets[index].size()), order);
        bytes.insert(bytes.end(), packets[index].begin(), packets[index].end());
    }
    return bytes;
}

inline Bytes demo_pcap() {
    return pcap({
        dns_frame(),
        tcp_frame(),
        icmp_frame(),
        ipv6_udp_frame(),
        dns_frame(false, true),
        arp_frame(),
        {0, 1, 2},
    });
}

}  // namespace wireatlas::synthetic
