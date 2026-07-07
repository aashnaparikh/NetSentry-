#include "detector/ARPDetector.h"

std::optional<ARPAlert> ARPDetector::inspect(const std::string& ip, const std::string& mac) {
    auto it = ip_mac_table_.find(ip);

    if (it == ip_mac_table_.end()) {
        ip_mac_table_.emplace(ip, mac);
        return std::nullopt;
    }

    if (it->second != mac) {
        ARPAlert alert{ip, it->second, mac};
        return alert;
    }

    return std::nullopt;
}
