#include "parser/TCPParser.h"

#include <netinet/tcp.h>
#include <netinet/in.h>
#include <cstring>

namespace {
constexpr int kMinTCPHeaderLen = 20;
}

TCPResult TCPParser::parse(const u_char* data, int len) {
    TCPResult result{};
    result.valid = false;
    result.src_port = 0;
    result.dst_port = 0;
    result.seq = 0;
    result.flag_syn = false;
    result.flag_ack = false;
    result.flag_fin = false;
    result.flag_rst = false;
    result.payload = nullptr;
    result.payload_len = 0;

    if (data == nullptr || len < kMinTCPHeaderLen) {
        return result;
    }

    const struct tcphdr* tcp_hdr = reinterpret_cast<const struct tcphdr*>(data);

    int header_len = tcp_hdr->th_off * 4;  // data offset, in 32-bit words
    if (header_len < kMinTCPHeaderLen || header_len > len) {
        return result;
    }

    result.src_port = ntohs(tcp_hdr->th_sport);
    result.dst_port = ntohs(tcp_hdr->th_dport);
    result.seq = ntohl(tcp_hdr->th_seq);
    result.flag_syn = (tcp_hdr->th_flags & TH_SYN) != 0;
    result.flag_ack = (tcp_hdr->th_flags & TH_ACK) != 0;
    result.flag_fin = (tcp_hdr->th_flags & TH_FIN) != 0;
    result.flag_rst = (tcp_hdr->th_flags & TH_RST) != 0;

    result.payload = data + header_len;
    result.payload_len = len - header_len;
    result.valid = true;

    return result;
}
