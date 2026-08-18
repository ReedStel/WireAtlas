# Changelog

All notable changes to WireAtlas are recorded here.

## 0.1.0 - 2026-08-18

### Added

- Defensive classic-PCAP reader with endian and timestamp-resolution detection
- Ethernet, VLAN, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, ARP, and DNS decoding
- Table, summary, and JSON reports with protocol, host, and count filters
- Synthetic capture generator using reserved documentation values
- Twenty-eight regression tests for valid, truncated, malformed, and cyclic inputs
- Cross-platform builds, sanitizers, and a bounded libFuzzer CI smoke test
