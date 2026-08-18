# Design notes

WireAtlas keeps file framing, packet decoding, and presentation separate. That makes malformed-input
behavior testable without launching the CLI and keeps JSON details out of protocol code.

## Data flow

1. `pcap_reader` reads the 24-byte global header, detects byte order and timestamp units from the
   magic number, then reads bounded packet records.
2. `packet_decoder` receives one immutable byte span at a time. Ethernet chooses the network layer;
   the network layer chooses the transport layer; a DNS payload is decoded only on port 53.
3. Each layer adds facts to a `PacketSummary`. A protocol-level `ParseError` records a byte offset on
   that summary, allowing later packets to continue.
4. `analyse_capture` applies filters and produces deterministic protocol counts.
5. `report` renders the same model as a terminal table or JSON.

## Parsing invariants

- No read occurs before the remaining span is checked.
- Declared lengths must fit inside both their parent protocol and captured bytes.
- DNS compression pointers must stay inside the message, may jump at most 16 times, and may not
  revisit an offset.
- TCP data offsets, UDP lengths, IP header lengths, and IP payload lengths are validated before a
  child protocol receives a span.
- A capture may contain at most 1,000,000 records, 512 MiB of decoded packet bytes, and 16 MiB in any
  one record.

## Error model

A broken global header or record boundary makes the file structurally ambiguous, so reading stops
with a standard exception. A malformed frame has a known boundary from the PCAP record header, so
the decoder marks only that packet and continues. Unsupported Ethernet payloads remain valid packet
summaries with their EtherType shown.

## Intentional tradeoffs

WireAtlas stores parsed records before analysing them. The 512 MiB cap makes that predictable and
keeps the public API simple; a production-scale version could stream summaries to a sink. IPv6
extension headers, IP fragment reassembly, TCP stream reassembly, checksums, DNS answer records, and
PCAPNG blocks are intentionally outside version 0.1.0.

No third-party runtime library is used. That leaves more code to maintain in the JSON renderer, but
keeps the binary portable and makes the binary-format work visible.
