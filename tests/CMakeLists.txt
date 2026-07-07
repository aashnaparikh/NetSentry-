find_package(GTest REQUIRED)
include(GoogleTest)

file(GLOB TEST_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/test_*.cpp)

add_executable(netsentry_tests ${TEST_SOURCES})
target_include_directories(netsentry_tests PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(netsentry_tests PRIVATE netsentry_lib GTest::GTest GTest::Main ${PCAP_LIB})

gtest_discover_tests(netsentry_tests)
