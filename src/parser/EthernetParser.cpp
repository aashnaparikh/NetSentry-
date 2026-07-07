#include "parser/EthernetParser.h"

#include <netinet/in.h>
#include <cstring>
#include <cstdio>

namespace {
constexpr int kEthernetHeaderLen = 14;
}

EthernetResult EthernetParser::parse(const u_char* data, int len) {
    EthernetResult result{};
    result.valid = false;
    result.payload = nullptr;
    result.payload_len = 0;

    if (data == nullptr || len < kEthernetHeaderLen) {
        return result;
    }

    std::memcpy(result.header.dst_mac.data(), data, 6);
    std::memcpy(result.header.src_mac.data(), data + 6, 6);

    uint16_t ethertype_net;
    std::memcpy(&ethertype_net, data + 12, 2);
    result.header.ethertype = ntohs(ethertype_net);

    result.payload = data + kEthernetHeaderLen;
    result.payload_len = len - kEthernetHeaderLen;
    result.valid = true;

    return result;
}

std::string EthernetParser::macToString(const std::array<uint8_t, 6>& mac) {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}
