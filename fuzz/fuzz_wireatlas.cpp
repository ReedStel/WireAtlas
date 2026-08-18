#include <cstddef>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

#include "wireatlas/packet_decoder.hpp"
#include "wireatlas/pcap_reader.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, const std::size_t size) {
    if (size == 0) return 0;

    if ((data[0] & 1U) == 0) {
        wireatlas::PacketRecord record;
        record.index = 1;
        record.original_length = size > UINT32_MAX ? UINT32_MAX : static_cast<std::uint32_t>(size);
        record.bytes.assign(data + 1, data + size);
        static_cast<void>(wireatlas::decode_packet(record, wireatlas::ethernet_link_type));
        return 0;
    }

    try {
        const std::string bytes(reinterpret_cast<const char*>(data + 1), size - 1);
        std::istringstream input(bytes, std::ios::in | std::ios::binary);
        const auto capture = wireatlas::read_pcap(input);
        static_cast<void>(wireatlas::analyse_capture(capture));
    } catch (const std::exception&) {
        // Invalid PCAP structure is an expected fuzzing outcome.
    }
    return 0;
}
