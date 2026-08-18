#pragma once

#include <cstdint>

#include "wireatlas/model.hpp"

namespace wireatlas {

PacketSummary decode_packet(const PacketRecord& record, std::uint32_t link_type);
Analysis analyse_capture(const Capture& capture, const PacketFilter& filter = {});

}  // namespace wireatlas
