#pragma once

#include <cstdint>
#include <sys/types.h>

struct UDPResult {
    bool valid;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    const u_char* payload;
    int payload_len;
};

class UDPParser {
public:
    static UDPResult parse(const u_char* data, int len);
};
