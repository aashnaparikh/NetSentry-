#include <gtest/gtest.h>
#include "parser/IPParser.h"

#include <array>

namespace {

// Builds a minimal, valid 20-byte IPv4 header:
//   version=4, IHL=5 (20 bytes), TTL=64, protocol=6 (TCP),
//   src=192.168.1.1, dst=10.0.0.1
std::array<u_char, 20> makeValidIPv4Header() {
    return {
        0x45, 0x00,             // version/IHL, TOS
        0x00, 0x14,             // total length = 20
        0x00, 0x00,             // identification
        0x00, 0x00,             // flags/fragment offset
        0x40,                   // TTL = 64
        0x06,                   // protocol = TCP
        0x00, 0x00,             // header checksum
        192, 168, 1, 1,         // src ip = 192.168.1.1
        10, 0, 0, 1              // dst ip = 10.0.0.1
    };
}

}  // namespace

TEST(IPParserTest, ValidHeaderParsesFields) {
    auto packet = makeValidIPv4Header();

    IPResult result = IPParser::parse(packet.data(), static_cast<int>(packet.size()));

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.protocol, 6);
    EXPECT_EQ(result.src_ip, "192.168.1.1");
    EXPECT_EQ(result.dst_ip, "10.0.0.1");
    EXPECT_EQ(result.ttl, 64);
}

TEST(IPParserTest, TooShortHeaderIsInvalid) {
    u_char packet[10] = {0};

    IPResult result = IPParser::parse(packet, sizeof(packet));

    EXPECT_FALSE(result.valid);
}

TEST(IPParserTest, HeaderLenComputedFromIHL) {
    auto packet = makeValidIPv4Header();

    IPResult result = IPParser::parse(packet.data(), static_cast<int>(packet.size()));

    EXPECT_TRUE(result.valid);
    EXPECT_EQ(result.header_len, 20);  // IHL=5 * 4 bytes
}
