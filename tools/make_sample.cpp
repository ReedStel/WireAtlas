#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

#include "synthetic_capture.hpp"

int main(const int argc, char* argv[]) {
    if (argc > 2) {
        std::cerr << "Usage: wireatlas-sample [output.pcap]\n";
        return 2;
    }
    const std::filesystem::path path = argc == 2 ? argv[1] : "synthetic-demo.pcap";
    try {
        const auto bytes = wireatlas::synthetic::demo_pcap();
        std::ofstream output(path, std::ios::binary);
        if (!output) throw std::runtime_error("could not open output file");
        output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (!output) throw std::runtime_error("could not write complete capture");
        std::cout << "Wrote " << bytes.size() << " bytes of synthetic traffic to " << path << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "wireatlas-sample: " << error.what() << '\n';
        return 1;
    }
}
