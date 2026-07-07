#include "parser/IPParser.h"

#include <netinet/ip.h>
#include <arpa/inet.h>
#include <cstring>

namespace {
constexpr int kMinIPHeaderLen = 20;
}

IPResult IPParser::parse(const u_char* data, int len) {
    IPResult result{};
    result.valid = false;
    result.protocol = 0;
    result.ttl = 0;
    result.payload = nullptr;
    result.payload_len = 0;
    result.header_len = 0;

    if (data == nullptr || len < kMinIPHeaderLen) {
        return result;
    }

    const struct ip* ip_hdr = reinterpret_cast<const struct ip*>(data);

    int header_len = ip_hdr->ip_hl * 4;  // ip_hl is in 32-bit words
    if (header_len < kMinIPHeaderLen || header_len > len) {
        return result;
    }

    result.header_len = header_len;
    result.ttl = ip_hdr->ip_ttl;
    result.protocol = ip_hdr->ip_p;
    result.src_ip = inet_ntoa(ip_hdr->ip_src);
    result.dst_ip = inet_ntoa(ip_hdr->ip_dst);

    result.payload = data + header_len;
    result.payload_len = len - header_len;
    result.valid = true;

    return result;
}
