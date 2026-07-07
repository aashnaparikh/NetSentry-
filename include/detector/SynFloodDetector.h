#pragma once

#include <string>
#include <unordered_map>
#include <chrono>
#include <optional>

struct SynFloodAlert {
    std::string src_ip;
    int syn_count;
};

// Detects SYN floods by tracking, per source IP, the count of pure SYN
// (SYN set, ACK unset) packets seen within a sliding time window.
class SynFloodDetector {
public:
    explicit SynFloodDetector(int threshold = 100, int window_seconds = 5);

    std::optional<SynFloodAlert> inspect(const std::string& src_ip, bool is_syn, bool is_ack);

private:
    struct SynEntry {
        int count;
        std::chrono::steady_clock::time_point window_start;
    };

    int threshold_;
    int window_seconds_;
    std::unordered_map<std::string, SynEntry> tracker_;
};
