#include "capture/PacketCapture.h"

#include <iostream>

PacketCapture::PacketCapture(const std::string& interface, const std::string& filter)
    : interface_(interface), filter_expr_(filter) {}

PacketCapture::~PacketCapture() {
    if (handle_ != nullptr) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

bool PacketCapture::open() {
    char errbuf[PCAP_ERRBUF_SIZE];
    errbuf[0] = '\0';

    handle_ = pcap_open_live(interface_.c_str(), 65535, 1, 1000, errbuf);
    if (handle_ == nullptr) {
        std::cerr << "PacketCapture: failed to open interface \"" << interface_
                   << "\": " << errbuf << std::endl;
        return false;
    }

    if (!filter_expr_.empty()) {
        struct bpf_program fp;
        if (pcap_compile(handle_, &fp, filter_expr_.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "PacketCapture: failed to compile filter \"" << filter_expr_
                       << "\": " << pcap_geterr(handle_) << std::endl;
            return false;
        }

        if (pcap_setfilter(handle_, &fp) == -1) {
            std::cerr << "PacketCapture: failed to apply filter \"" << filter_expr_
                       << "\": " << pcap_geterr(handle_) << std::endl;
            pcap_freecode(&fp);
            return false;
        }

        pcap_freecode(&fp);
    }

    return true;
}

void PacketCapture::packetCallback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    auto* handler = reinterpret_cast<PacketHandler*>(user);
    if (handler == nullptr || !(*handler)) {
        return;
    }

    ParsedPacketMeta meta;
    meta.data = packet;
    meta.len = static_cast<int>(header->caplen);
    meta.ts = header->ts;

    (*handler)(meta);
}

void PacketCapture::startCapture(PacketHandler handler) {
    if (handle_ == nullptr) {
        std::cerr << "PacketCapture: cannot start capture, handle not open" << std::endl;
        return;
    }

    // pcap_loop's user pointer is passed through to the static callback,
    // which reconstructs the std::function from it.
    pcap_loop(handle_, -1, &PacketCapture::packetCallback, reinterpret_cast<u_char*>(&handler));
}

void PacketCapture::stopCapture() {
    if (handle_ != nullptr) {
        pcap_breakloop(handle_);
    }
}

std::string PacketCapture::getInterface() const {
    return interface_;
}
