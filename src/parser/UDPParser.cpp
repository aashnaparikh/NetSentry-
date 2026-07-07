#include "parser/UDPParser.h"

#include <netinet/udp.h>
#include <netinet/in.h>
#include <cstring>

namespace {
constexpr int kUDPHeaderLen = 8;
}

UDPResult UDPParser::parse(const u_char* data, int len) {
    UDPResult result{};
    result.valid = false;
    result.src_port = 0;
    result.dst_port = 0;
    result.length = 0;
    result.payload = nullptr;
    result.payload_len = 0;

    if (data == nullptr || len < kUDPHeaderLen) {
        return result;
    }

    const struct udphdr* udp_hdr = reinterpret_cast<const struct udphdr*>(data);

    result.src_port = ntohs(udp_hdr->uh_sport);
    result.dst_port = ntohs(udp_hdr->uh_dport);
    result.length = ntohs(udp_hdr->uh_ulen);

    result.payload = data + kUDPHeaderLen;
    result.payload_len = static_cast<int>(result.length) - kUDPHeaderLen;
    if (result.payload_len < 0) {
        result.payload_len = 0;
    }
    result.valid = true;

    return result;
}
