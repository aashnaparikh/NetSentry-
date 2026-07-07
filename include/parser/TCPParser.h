#pragma once

#include <cstdint>
#include <sys/types.h>

struct TCPResult {
    bool valid;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    bool flag_syn;
    bool flag_ack;
    bool flag_fin;
    bool flag_rst;
    const u_char* payload;
    int payload_len;
};

class TCPParser {
public:
    static TCPResult parse(const u_char* data, int len);
};
