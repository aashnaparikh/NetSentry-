#include "detector/PortScanDetector.h"

PortScanDetector::PortScanDetector(int threshold, int window_seconds)
    : threshold_(threshold), window_seconds_(window_seconds) {}

std::optional<PortScanAlert> PortScanDetector::inspect(const std::string& src_ip, uint16_t dst_port) {
    auto now = std::chrono::steady_clock::now();

    auto it = tracker_.find(src_ip);
    if (it == tracker_.end()) {
        PortEntry entry;
        entry.window_start = now;
        it = tracker_.emplace(src_ip, std::move(entry)).first;
    }

    PortEntry& entry = it->second;

    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - entry.window_start).count();
    if (elapsed > window_seconds_) {
        entry.ports.clear();
        entry.window_start = now;
    }

    entry.ports.insert(dst_port);

    if (static_cast<int>(entry.ports.size()) >= threshold_) {
        return PortScanAlert{src_ip, static_cast<int>(entry.ports.size())};
    }

    return std::nullopt;
}
