#pragma once

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <optional>
#include <cstdint>

struct PortScanAlert {
    std::string src_ip;
    int unique_ports_hit;
};

// Detects port scans by tracking, per source IP, the set of unique
// destination ports contacted within a sliding time window.
class PortScanDetector {
public:
    explicit PortScanDetector(int threshold = 15, int window_seconds = 10);

    std::optional<PortScanAlert> inspect(const std::string& src_ip, uint16_t dst_port);

private:
    struct PortEntry {
        std::unordered_set<uint16_t> ports;
        std::chrono::steady_clock::time_point window_start;
    };

    int threshold_;
    int window_seconds_;
    std::unordered_map<std::string, PortEntry> tracker_;
};
