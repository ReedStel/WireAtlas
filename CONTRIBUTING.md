# Contributing

Thanks for taking the time to improve WireAtlas.

## Before opening a change

Open an issue describing the behavior, the smallest useful scope, and how you plan to test it. For a
security issue, follow [SECURITY.md](SECURITY.md) instead of opening a public report.

Never attach real captures, credentials, tokens, internal hostnames, routable addresses, customer
data, or employer-specific details. A regression must be recreated with the synthetic builder in
`tools/synthetic_capture.hpp` and documentation-only values.

## Development checks

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DWIREATLAS_WARNINGS_AS_ERRORS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

Keep parsing bounded, preserve useful byte offsets, and add a failure-path test for every new length
field or pointer. Format C++ changes with the repository `.clang-format` file.

## License for contributions

WireAtlas is source-available rather than open source. Section 4 of [LICENSE](LICENSE) allows you to
prepare a modification solely for submission to this repository and explains the rights granted by
submitting it. Do not submit a change unless you own it and agree to those terms.
