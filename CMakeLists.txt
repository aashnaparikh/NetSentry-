cmake_minimum_required(VERSION 3.16)
project(NetSentry VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_library(PCAP_LIB pcap REQUIRED)

include_directories(${CMAKE_SOURCE_DIR}/include)

add_compile_options(-Wall -Wextra -Wpedantic)

# Collect all library sources (everything except main.cpp) into a static
# library so both the netsentry executable and the test executable can
# link against the same compiled code without recompiling for tests.
file(GLOB_RECURSE LIB_SOURCES CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/src/*.cpp)
list(REMOVE_ITEM LIB_SOURCES ${CMAKE_SOURCE_DIR}/src/main.cpp)

add_library(netsentry_lib STATIC ${LIB_SOURCES})
target_include_directories(netsentry_lib PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(netsentry_lib PUBLIC ${PCAP_LIB})

add_executable(netsentry src/main.cpp)
target_link_libraries(netsentry PRIVATE netsentry_lib ${PCAP_LIB})

enable_testing()
add_subdirectory(tests)
