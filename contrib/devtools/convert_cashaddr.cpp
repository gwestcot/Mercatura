#include <cashaddr.h>
#include <iostream>
#include <string>

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "Usage: convert_cashaddr <old_addr> <new_prefix>\n";
        return 1;
    }

    const std::string old_addr = argv[1];
    const std::string new_prefix = argv[2];

    auto decoded = cashaddr::Decode(old_addr, "");
    const std::string& old_prefix = decoded.first;
    const auto& payload = decoded.second;

    if (old_prefix.empty() || payload.empty()) {
        std::cerr << "Decode failed: " << old_addr << "\n";
        return 2;
    }

    std::cout << cashaddr::Encode(new_prefix, payload) << "\n";
    return 0;
}
