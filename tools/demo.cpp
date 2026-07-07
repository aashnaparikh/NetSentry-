// NetSentry offline demo.
//
// Runs synthetic (but structurally real) Ethernet/IP/TCP/ARP frames through
// the exact same parser -> detector -> logger pipeline used by main.cpp,
// without needing root privileges or a live network interface. This exists
// so the detection logic can be demonstrated (e.g. in a README or CI run)
// without requiring a real network capture.
#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <thread>
#include <vector>

#include "parser/EthernetParser.h"
#include "parser/IPParser.h"
#include "parser/TCPParser.h"
#include "detector/PortScanDetector.h"
#include "detector/SynFloodDetector.h"
#include "detector/ARPDetector.h"
#include "logger/AlertLogger.h"

namespace {

std::vector<u_char> makeTcpFrame(const std::array<uint8_t, 4>& src_ip,
                                   const std::array<uint8_t, 4>& dst_ip,
                                   uint16_t src_port, uint16_t dst_port, bool syn, bool ack) {
    std::vector<u_char> frame;

    // Ethernet header (14 bytes): dst MAC, src MAC, ethertype = IPv4
    uint8_t eth[14] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x08, 0x00
    };
    frame.insert(frame.end(), eth, eth + 14);

    // IPv4 header (20 bytes): version/IHL, TTL=64, protocol=TCP
    uint8_t ip[20] = {
        0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        src_ip[0], src_ip[1], src_ip[2], src_ip[3],
        dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]
    };
    frame.insert(frame.end(), ip, ip + 20);

    // TCP header (20 bytes)
    uint8_t flags = (syn ? 0x02 : 0x00) | (ack ? 0x10 : 0x00);
    uint8_t tcp[20] = {
        static_cast<uint8_t>(src_port >> 8), static_cast<uint8_t>(src_port & 0xFF),
        static_cast<uint8_t>(dst_port >> 8), static_cast<uint8_t>(dst_port & 0xFF),
        0x00, 0x00, 0x00, 0x01,   // sequence number
        0x00, 0x00, 0x00, 0x00,   // ack number
        0x50, flags,               // data offset = 5, flags
        0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00
    };
    frame.insert(frame.end(), tcp, tcp + 20);

    return frame;
}

std::vector<u_char> makeArpFrame(const std::array<uint8_t, 4>& sender_ip,
                                   const std::array<uint8_t, 6>& sender_mac) {
    std::vector<u_char> frame;

    uint8_t eth[14] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   // broadcast dst
        sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5],
        0x08, 0x06                             // ethertype = ARP
    };
    frame.insert(frame.end(), eth, eth + 14);

    // ARP payload (28 bytes): hw type, proto type, hw len, proto len, opcode,
    // sender MAC (offset 8), sender IP (offset 14), target MAC, target IP
    uint8_t arp[28] = {0};
    arp[1] = 0x01;  // hw type = Ethernet
    arp[3] = 0x08;  // proto type = IPv4
    arp[4] = 6;     // hw addr len
    arp[5] = 4;     // proto addr len
    arp[7] = 0x01;  // opcode = request
    std::memcpy(arp + 8, sender_mac.data(), 6);
    std::memcpy(arp + 14, sender_ip.data(), 4);
    frame.insert(frame.end(), arp, arp + 28);

    return frame;
}

void feedTcpFrame(const std::vector<u_char>& frame, PortScanDetector& scan, SynFloodDetector& flood,
                    AlertLogger& logger) {
    EthernetResult eth = EthernetParser::parse(frame.data(), static_cast<int>(frame.size()));
    if (!eth.valid || eth.header.ethertype != 0x0800) return;

    IPResult ip = IPParser::parse(eth.payload, eth.payload_len);
    if (!ip.valid || ip.protocol != 6) return;

    TCPResult tcp = TCPParser::parse(ip.payload, ip.payload_len);
    if (!tcp.valid) return;

    if (auto alert = scan.inspect(ip.src_ip, tcp.dst_port)) {
        logger.log(Severity::CRITICAL, "PORT_SCAN", alert->src_ip,
                    std::to_string(alert->unique_ports_hit) + " unique ports in 10s window");
    }
    if (auto alert = flood.inspect(ip.src_ip, tcp.flag_syn, tcp.flag_ack)) {
        logger.log(Severity::CRITICAL, "SYN_FLOOD", alert->src_ip,
                    std::to_string(alert->syn_count) + " SYNs in 5s window");
    }
}

void feedArpFrame(const std::vector<u_char>& frame, ARPDetector& arp_detector, AlertLogger& logger) {
    EthernetResult eth = EthernetParser::parse(frame.data(), static_cast<int>(frame.size()));
    if (!eth.valid || eth.header.ethertype != 0x0806) return;
    if (eth.payload_len < 18) return;

    char ip_buf[16];
    std::snprintf(ip_buf, sizeof(ip_buf), "%d.%d.%d.%d",
                   eth.payload[14], eth.payload[15], eth.payload[16], eth.payload[17]);
    char mac_buf[18];
    std::snprintf(mac_buf, sizeof(mac_buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                   eth.payload[8], eth.payload[9], eth.payload[10],
                   eth.payload[11], eth.payload[12], eth.payload[13]);

    if (auto alert = arp_detector.inspect(ip_buf, mac_buf)) {
        logger.log(Severity::CRITICAL, "ARP_SPOOF", alert->ip,
                    "MAC changed from " + alert->known_mac + " to " + alert->new_mac);
    }
}

}  // namespace

int main() {
    AlertLogger logger(false);
    PortScanDetector scan_detector(15, 10);
    SynFloodDetector flood_detector(100, 5);
    ARPDetector arp_detector;

    logger.log(Severity::INFO, "STARTUP", "local", "NetSentry demo replaying synthetic traffic");

    // --- Port scan: one source IP touching 20 distinct destination ports ---
    std::array<uint8_t, 4> scanner_ip = {192, 168, 1, 105};
    std::array<uint8_t, 4> scan_target = {192, 168, 1, 1};
    for (int port = 20; port < 40; ++port) {
        auto frame = makeTcpFrame(scanner_ip, scan_target, 50000, static_cast<uint16_t>(port), true, false);
        feedTcpFrame(frame, scan_detector, flood_detector, logger);
    }

    // --- SYN flood: one source IP sending 120 pure SYNs to the same port ---
    std::array<uint8_t, 4> flooder_ip = {10, 0, 0, 44};
    std::array<uint8_t, 4> flood_target = {10, 0, 0, 1};
    for (int i = 0; i < 120; ++i) {
        auto frame = makeTcpFrame(flooder_ip, flood_target, static_cast<uint16_t>(40000 + i), 22, true, false);
        feedTcpFrame(frame, scan_detector, flood_detector, logger);
    }

    // --- ARP spoof: same IP claimed by two different MAC addresses ---
    std::array<uint8_t, 4> gateway_ip = {192, 168, 1, 1};
    std::array<uint8_t, 6> real_mac = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    std::array<uint8_t, 6> spoofed_mac = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

    feedArpFrame(makeArpFrame(gateway_ip, real_mac), arp_detector, logger);
    feedArpFrame(makeArpFrame(gateway_ip, spoofed_mac), arp_detector, logger);

    logger.log(Severity::INFO, "SHUTDOWN", "local", "NetSentry demo finished");

    return 0;
}
