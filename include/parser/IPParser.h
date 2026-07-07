#pragma once

#include <cstdint>
#include <string>
#include <sys/types.h>

struct IPResult {
    bool valid;
    std::string src_ip;
    std::string dst_ip;
    uint8_t protocol;
    uint8_t ttl;
    const u_char* payload;
    int payload_len;
    int header_len;
};

class IPParser {
public:
    static IPResult parse(const u_char* data, int len);
};
