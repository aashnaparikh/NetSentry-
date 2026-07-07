#pragma once

#include <string>
#include <unordered_map>
#include <optional>

struct ARPAlert {
    std::string ip;
    std::string known_mac;
    std::string new_mac;
};

// Detects ARP spoofing by tracking a table of IP -> MAC bindings and
// flagging any IP whose MAC address changes.
class ARPDetector {
public:
    std::optional<ARPAlert> inspect(const std::string& ip, const std::string& mac);

private:
    std::unordered_map<std::string, std::string> ip_mac_table_;
};
