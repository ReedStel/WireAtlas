# Working safely with packet captures

Packet captures are data, but they can be highly sensitive and should be handled like logs or a
database export.

## Before inspection

- Obtain the capture lawfully and only from a network you are authorized to inspect.
- Store it outside synchronized or public folders unless sharing is explicitly approved.
- Do not rename a real capture to match the synthetic demo and accidentally commit it.
- Run WireAtlas as an ordinary user in a disposable environment when the source is untrusted.

## What a capture can reveal

Depending on the protocols and capture point, a file may contain device addresses, internal
topology, DNS questions, service names, session identifiers, personal data, or entire unencrypted
application messages. JSON output can repeat those values, so protect reports the same way as the
original capture.

## Repository safeguards

The `.gitignore` excludes `*.pcap` and `*.pcapng`. Tests construct packets in memory from reserved
documentation ranges, and `wireatlas-sample` generates a reproducible demonstration locally. File
type filters are useful guardrails, not a substitute for reviewing staged changes before publishing.

## Parser limits

Version 0.1.0 accepts classic PCAP 2.4 with Ethernet link type. It rejects individual packets above
16 MiB, captures above 1,000,000 packet records or 512 MiB of decoded bytes, invalid timestamp
fractions, inconsistent captured/original lengths, and incomplete record boundaries.
