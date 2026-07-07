#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <sstream>
#include <array>

#include "capture/PacketCapture.h"
#include "parser/EthernetParser.h"
#include "parser/IPParser.h"
#include "parser/TCPParser.h"
#include "parser/UDPParser.h"
#include "detector/PortScanDetector.h"
#include "detector/SynFloodDetector.h"
#include "detector/ARPDetector.h"
#include "logger/AlertLogger.h"

namespace {

constexpr uint16_t kEthertypeIPv4 = 0x0800;
constexpr uint16_t kEthertypeARP = 0x0806;
constexpr uint8_t kProtoTCP = 6;

volatile std::sig_atomic_t g_running = 1;
PacketCapture* g_capture = nullptr;

void handleSigint(int /*signum*/) {
    g_running = 0;
    if (g_capture != nullptr) {
        g_capture->stopCapture();
    }
}

void printUsage(const char* prog) {
    std::cerr << "Usage: " << prog << " -i <interface> [-f <bpf filter>] [-o <logfile>] "
              << "[--port-threshold <n>] [--syn-threshold <n>]\n";
}

std::string macBytesToString(const u_char* mac) {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

std::string ipBytesToString(const u_char* ip) {
    std::ostringstream oss;
    oss << static_cast<int>(ip[0]) << "." << static_cast<int>(ip[1]) << "."
        << static_cast<int>(ip[2]) << "." << static_cast<int>(ip[3]);
    return oss.str();
}

}  // namespace

int main(int argc, char** argv) {
    std::string interface;
    std::string filter;
    std::string logfile = "netsentry.log";
    int port_threshold = 15;
    int syn_threshold = 100;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-i" && i + 1 < argc) {
            interface = argv[++i];
        } else if (arg == "-f" && i + 1 < argc) {
            filter = argv[++i];
        } else if (arg == "-o" && i + 1 < argc) {
            logfile = argv[++i];
        } else if (arg == "--port-threshold" && i + 1 < argc) {
            port_threshold = std::atoi(argv[++i]);
        } else if (arg == "--syn-threshold" && i + 1 < argc) {
            syn_threshold = std::atoi(argv[++i]);
        } else if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            return 0;
        }
    }

    if (interface.empty()) {
        printUsage(argv[0]);
        return 1;
    }

    std::signal(SIGINT, handleSigint);

    AlertLogger logger(true, logfile);
    PortScanDetector port_scan_detector(port_threshold, 10);
    SynFloodDetector syn_flood_detector(syn_threshold, 5);
    ARPDetector arp_detector;
    PacketCapture capture(interface, filter);
    g_capture = &capture;

    if (!capture.open()) {
        return 1;
    }

    auto handler = [&](const ParsedPacketMeta& meta) {
        EthernetResult eth = EthernetParser::parse(meta.data, meta.len);
        if (!eth.valid) {
            return;
        }

        if (eth.header.ethertype == kEthertypeIPv4) {
            IPResult ip = IPParser::parse(eth.payload, eth.payload_len);
            if (!ip.valid) {
                return;
            }

            if (ip.protocol == kProtoTCP) {
                TCPResult tcp = TCPParser::parse(ip.payload, ip.payload_len);
                if (!tcp.valid) {
                    return;
                }

                auto scan_alert = port_scan_detector.inspect(ip.src_ip, tcp.dst_port);
                if (scan_alert) {
                    std::ostringstream details;
                    details << scan_alert->unique_ports_hit << " unique ports in 10s window";
                    logger.log(Severity::CRITICAL, "PORT_SCAN", scan_alert->src_ip, details.str());
                }

                auto syn_alert = syn_flood_detector.inspect(ip.src_ip, tcp.flag_syn, tcp.flag_ack);
                if (syn_alert) {
                    std::ostringstream details;
                    details << syn_alert->syn_count << " SYNs in 5s window";
                    logger.log(Severity::CRITICAL, "SYN_FLOOD", syn_alert->src_ip, details.str());
                }
            }
        } else if (eth.header.ethertype == kEthertypeARP) {
            // ARP payload layout (within eth.payload):
            //   offset 8:  sender MAC (6 bytes)
            //   offset 14: sender IP   (4 bytes)
            if (eth.payload_len >= 18) {
                std::string sender_mac = macBytesToString(eth.payload + 8);
                std::string sender_ip = ipBytesToString(eth.payload + 14);

                auto arp_alert = arp_detector.inspect(sender_ip, sender_mac);
                if (arp_alert) {
                    std::ostringstream details;
                    details << "MAC changed from " << arp_alert->known_mac << " to " << arp_alert->new_mac;
                    logger.log(Severity::CRITICAL, "ARP_SPOOF", arp_alert->ip, details.str());
                }
            }
        }
    };

    logger.log(Severity::INFO, "STARTUP", "local", "NetSentry listening on " + interface);

    capture.startCapture(handler);

    logger.log(Severity::INFO, "SHUTDOWN", "local", "NetSentry stopped cleanly");

    return 0;
}
