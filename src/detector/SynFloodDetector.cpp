#include "detector/SynFloodDetector.h"

SynFloodDetector::SynFloodDetector(int threshold, int window_seconds)
    : threshold_(threshold), window_seconds_(window_seconds) {}

std::optional<SynFloodAlert> SynFloodDetector::inspect(const std::string& src_ip, bool is_syn, bool is_ack) {
    // Only pure SYN packets (SYN set, ACK unset) count toward a flood.
    if (!is_syn || is_ack) {
        return std::nullopt;
    }

    auto now = std::chrono::steady_clock::now();

    auto it = tracker_.find(src_ip);
    if (it == tracker_.end()) {
        SynEntry entry;
        entry.count = 0;
        entry.window_start = now;
        it = tracker_.emplace(src_ip, entry).first;
    }

    SynEntry& entry = it->second;

    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - entry.window_start).count();
    if (elapsed > window_seconds_) {
        entry.count = 0;
        entry.window_start = now;
    }

    entry.count += 1;

    if (entry.count >= threshold_) {
        return SynFloodAlert{src_ip, entry.count};
    }

    return std::nullopt;
}
