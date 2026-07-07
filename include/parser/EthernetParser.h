#pragma once

#include <cstdint>
#include <array>
#include <string>
#include <sys/types.h>

struct EthernetHeader {
    std::array<uint8_t, 6> dst_mac;
    std::array<uint8_t, 6> src_mac;
    uint16_t ethertype;  // 0x0800 = IPv4, 0x0806 = ARP
};

struct EthernetResult {
    bool valid;
    EthernetHeader header;
    const u_char* payload;
    int payload_len;
};

class EthernetParser {
public:
    static EthernetResult parse(const u_char* data, int len);
    static std::string macToString(const std::array<uint8_t, 6>& mac);
};
