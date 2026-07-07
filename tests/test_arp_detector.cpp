#include <gtest/gtest.h>
#include "detector/ARPDetector.h"

TEST(ARPDetectorTest, FirstTimeSeeingIpProducesNoAlert) {
    ARPDetector detector;

    auto alert = detector.inspect("192.168.1.1", "AA:BB:CC:DD:EE:FF");

    EXPECT_FALSE(alert.has_value());
}

TEST(ARPDetectorTest, SameIpSameMacProducesNoAlert) {
    ARPDetector detector;

    detector.inspect("192.168.1.1", "AA:BB:CC:DD:EE:FF");
    auto alert = detector.inspect("192.168.1.1", "AA:BB:CC:DD:EE:FF");

    EXPECT_FALSE(alert.has_value());
}

TEST(ARPDetectorTest, SameIpDifferentMacProducesAlert) {
    ARPDetector detector;

    detector.inspect("192.168.1.1", "AA:BB:CC:DD:EE:FF");
    auto alert = detector.inspect("192.168.1.1", "11:22:33:44:55:66");

    ASSERT_TRUE(alert.has_value());
    EXPECT_EQ(alert->known_mac, "AA:BB:CC:DD:EE:FF");
    EXPECT_EQ(alert->new_mac, "11:22:33:44:55:66");
}
