#include <gtest/gtest.h>
#include "parser/EthernetParser.h"

TEST(EthernetParserTest, ValidFrameParsesHeaderAndPayload) {
    // 6 bytes dst MAC + 6 bytes src MAC + 2 bytes ethertype (IPv4) + 6 bytes payload = 20 bytes
    u_char frame[20] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  // dst MAC
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,  // src MAC
        0x08, 0x00,                          // ethertype = IPv4
        'p', 'a', 'y', 'l', 'o', 'a'          // 6 bytes of payload
    };

    EthernetResult result = EthernetParser::parse(frame, sizeof(frame));

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.header.ethertype, 0x0800);
    EXPECT_EQ(result.payload_len, 6);
}

TEST(EthernetParserTest, TooShortFrameIsInvalid) {
    u_char frame[10] = {0};

    EthernetResult result = EthernetParser::parse(frame, sizeof(frame));

    EXPECT_FALSE(result.valid);
}

TEST(EthernetParserTest, MacToStringFormatsCorrectly) {
    std::array<uint8_t, 6> mac = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    EXPECT_EQ(EthernetParser::macToString(mac), "AA:BB:CC:DD:EE:FF");
}
