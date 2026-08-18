#pragma once

#include <filesystem>
#include <istream>

#include "wireatlas/model.hpp"

namespace wireatlas {

inline constexpr std::uint32_t ethernet_link_type = 1;
inline constexpr std::uint32_t maximum_packet_size = 16U * 1024U * 1024U;
inline constexpr std::size_t maximum_packet_count = 1'000'000U;
inline constexpr std::uint64_t maximum_capture_bytes = 512ULL * 1024ULL * 1024ULL;

Capture read_pcap(std::istream& input);
Capture read_pcap_file(const std::filesystem::path& path);

}  // namespace wireatlas
