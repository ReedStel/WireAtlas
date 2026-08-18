# Security policy

## Supported version

Security fixes are made on the latest commit of the `main` branch.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting feature for this repository. If that option is not
available, open a public issue containing only a request for a private reporting channel. Do not put
exploit details, packet captures, credentials, private addresses, or identifying data in a public
issue.

Include the affected version or commit, the smallest synthetic input that reproduces the issue, the
observed result, and the expected safe behavior. You should receive an acknowledgement before any
public disclosure is discussed.

## Operational boundary

WireAtlas is an educational offline parser, not a hardened sandbox. Do not run it with elevated
privileges. Treat captures as sensitive: they may expose addresses, queries, service names, and
unencrypted payload data even when the parser itself behaves correctly.
