#include <gtest/gtest.h>
#include "parser/TCPParser.h"

#include <array>

namespace {

// 20-byte TCP header: src_port=12345, dst_port=80, data offset=5 (20 bytes),
// flags configurable via the last byte-13 argument.
std::array<u_char, 20> makeTCPHeader(uint8_t flags) {
    return {
        0x30, 0x39,             // src port = 12345
        0x00, 0x50,             // dst port = 80
        0x00, 0x00, 0x00, 0x01, // sequence number
        0x00, 0x00, 0x00, 0x00, // ack number
        0x50,                   // data offset = 5 (20 bytes), reserved bits = 0
        flags,                  // flags
        0xFF, 0xFF,             // window size
        0x00, 0x00,             // checksum
        0x00, 0x00               // urgent pointer
    };
}

}  // namespace

TEST(TCPParserTest, ValidSynPacketParsesFields) {
    auto packet = makeTCPHeader(0x02);  // SYN only

    TCPResult result = TCPParser::parse(packet.data(), static_cast<int>(packet.size()));

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.src_port, 12345);
    EXPECT_EQ(result.dst_port, 80);
    EXPECT_TRUE(result.flag_syn);
    EXPECT_FALSE(result.flag_ack);
}

TEST(TCPParserTest, SynAckFlagsBothSet) {
    auto packet = makeTCPHeader(0x12);  // SYN + ACK

    TCPResult result = TCPParser::parse(packet.data(), static_cast<int>(packet.size()));

    EXPECT_TRUE(result.valid);
    EXPECT_TRUE(result.flag_syn);
    EXPECT_TRUE(result.flag_ack);
}

TEST(TCPParserTest, TooShortHeaderIsInvalid) {
    u_char packet[10] = {0};

    TCPResult result = TCPParser::parse(packet, sizeof(packet));

    EXPECT_FALSE(result.valid);
}
