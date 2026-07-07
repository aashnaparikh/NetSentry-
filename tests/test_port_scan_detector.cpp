#include <gtest/gtest.h>
#include "detector/PortScanDetector.h"

TEST(PortScanDetectorTest, NoAlertBelowThreshold) {
    PortScanDetector detector(15, 10);

    for (uint16_t port = 0; port < 14; ++port) {
        auto alert = detector.inspect("192.168.1.1", port);
        EXPECT_FALSE(alert.has_value());
    }
}

TEST(PortScanDetectorTest, AlertFiresAtThreshold) {
    PortScanDetector detector(15, 10);

    std::optional<PortScanAlert> alert;
    for (uint16_t port = 0; port < 15; ++port) {
        alert = detector.inspect("192.168.1.1", port);
    }

    ASSERT_TRUE(alert.has_value());
    EXPECT_EQ(alert->src_ip, "192.168.1.1");
    EXPECT_GE(alert->unique_ports_hit, 15);
}

TEST(PortScanDetectorTest, DifferentSourceIpsTrackedIndependently) {
    PortScanDetector detector(15, 10);

    for (uint16_t port = 0; port < 14; ++port) {
        auto alert_a = detector.inspect("192.168.1.1", port);
        auto alert_b = detector.inspect("10.0.0.1", port + 100);
        EXPECT_FALSE(alert_a.has_value());
        EXPECT_FALSE(alert_b.has_value());
    }
}
