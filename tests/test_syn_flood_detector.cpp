#include <gtest/gtest.h>
#include "detector/SynFloodDetector.h"

TEST(SynFloodDetectorTest, PureSynPacketsCountTowardThreshold) {
    SynFloodDetector detector(5, 5);

    std::optional<SynFloodAlert> alert;
    for (int i = 0; i < 5; ++i) {
        alert = detector.inspect("10.0.0.44", /*is_syn=*/true, /*is_ack=*/false);
    }

    ASSERT_TRUE(alert.has_value());
    EXPECT_EQ(alert->src_ip, "10.0.0.44");
    EXPECT_GE(alert->syn_count, 5);
}

TEST(SynFloodDetectorTest, SynAckPacketsDoNotCount) {
    SynFloodDetector detector(5, 5);

    std::optional<SynFloodAlert> alert;
    for (int i = 0; i < 10; ++i) {
        alert = detector.inspect("10.0.0.44", /*is_syn=*/true, /*is_ack=*/true);
    }

    EXPECT_FALSE(alert.has_value());
}

TEST(SynFloodDetectorTest, AlertFiresAfterThresholdPureSyns) {
    SynFloodDetector detector(100, 5);

    std::optional<SynFloodAlert> alert;
    for (int i = 0; i < 99; ++i) {
        alert = detector.inspect("10.0.0.44", true, false);
        EXPECT_FALSE(alert.has_value());
    }

    alert = detector.inspect("10.0.0.44", true, false);
    ASSERT_TRUE(alert.has_value());
    EXPECT_EQ(alert->syn_count, 100);
}
