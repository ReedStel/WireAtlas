#include <charconv>
#include <cstddef>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

#include "wireatlas/packet_decoder.hpp"
#include "wireatlas/pcap_reader.hpp"
#include "wireatlas/report.hpp"
#include "wireatlas/version.hpp"

namespace {

struct Options {
    std::string command;
    std::filesystem::path capture_path;
    wireatlas::PacketFilter filter;
    bool json{false};
};

void print_usage(std::ostream& output) {
    output << "WireAtlas — defensive, offline PCAP inspection\n\n"
           << "Usage:\n"
           << "  wireatlas inspect <capture.pcap> [options]\n"
           << "  wireatlas summary <capture.pcap> [options]\n"
           << "  wireatlas --help | --version\n\n"
           << "Options:\n"
           << "  --json               Emit machine-readable JSON\n"
           << "  --protocol <name>    Keep one decoded protocol (for example DNS or TCP)\n"
           << "  --host <address>     Keep packets with this source or destination address\n"
           << "  --limit <count>      Stop after this many matching packets\n\n"
           << "WireAtlas reads classic PCAP files only. It never captures or sends traffic.\n";
}

std::size_t parse_limit(const std::string_view value) {
    std::size_t result = 0;
    const auto* begin = value.data();
    const auto* end = value.data() + value.size();
    const auto parsed = std::from_chars(begin, end, result);
    if (parsed.ec != std::errc{} || parsed.ptr != end || result == 0) {
        throw std::invalid_argument("--limit requires a positive whole number");
    }
    return result;
}

Options parse_options(const int argc, char* argv[]) {
    if (argc < 3) throw std::invalid_argument("a command and capture path are required");
    Options options;
    options.command = argv[1];
    if (options.command != "inspect" && options.command != "summary") {
        throw std::invalid_argument("unknown command: " + options.command);
    }
    options.capture_path = argv[2];

    for (int index = 3; index < argc; ++index) {
        const std::string_view argument = argv[index];
        if (argument == "--json") {
            options.json = true;
        } else if (argument == "--protocol" || argument == "--host" || argument == "--limit") {
            if (index + 1 >= argc) {
                throw std::invalid_argument(std::string(argument) + " requires a value");
            }
            const std::string value = argv[++index];
            if (value.empty()) throw std::invalid_argument(std::string(argument) + " cannot be empty");
            if (argument == "--protocol") options.filter.protocol = value;
            else if (argument == "--host") options.filter.host = value;
            else options.filter.limit = parse_limit(value);
        } else {
            throw std::invalid_argument("unknown option: " + std::string(argument));
        }
    }
    return options;
}

}  // namespace

int main(const int argc, char* argv[]) {
    if (argc == 2) {
        const std::string_view argument = argv[1];
        if (argument == "--help" || argument == "-h") {
            print_usage(std::cout);
            return 0;
        }
        if (argument == "--version") {
            std::cout << "WireAtlas " << wireatlas::version << '\n';
            return 0;
        }
    }

    try {
        const auto options = parse_options(argc, argv);
        const auto capture = wireatlas::read_pcap_file(options.capture_path);
        const auto analysis = wireatlas::analyse_capture(capture, options.filter);
        if (options.json) {
            std::cout << wireatlas::render_json(analysis, options.command == "inspect");
        } else if (options.command == "inspect") {
            std::cout << wireatlas::render_table(analysis) << '\n'
                      << wireatlas::render_summary(analysis);
        } else {
            std::cout << wireatlas::render_summary(analysis);
        }
        return 0;
    } catch (const std::invalid_argument& error) {
        std::cerr << "wireatlas: " << error.what() << "\n\n";
        print_usage(std::cerr);
        return 2;
    } catch (const std::exception& error) {
        std::cerr << "wireatlas: " << error.what() << '\n';
        return 3;
    }
}
