#pragma once

#include <pcap.h>
#include <string>
#include <functional>
#include <cstdint>

// Metadata describing a single captured packet, handed to the user's
// PacketHandler callback.
struct ParsedPacketMeta {
    const u_char* data;
    int len;
    struct timeval ts;
};

using PacketHandler = std::function<void(const ParsedPacketMeta&)>;

// RAII wrapper around libpcap. Opens a live capture handle on construction
// (via open()), and guarantees the handle is closed on destruction.
class PacketCapture {
public:
    explicit PacketCapture(const std::string& interface, const std::string& filter = "");
    ~PacketCapture();

    // Non-copyable: this class owns a raw pcap_t* handle.
    PacketCapture(const PacketCapture&) = delete;
    PacketCapture& operator=(const PacketCapture&) = delete;

    // Opens the interface in promiscuous mode and applies the BPF filter
    // (if one was provided). Returns false and prints an error on failure.
    bool open();

    // Blocks, invoking `handler` for every captured packet, until
    // stopCapture() is called or an error occurs.
    void startCapture(PacketHandler handler);

    // Requests that a running startCapture() loop stop.
    void stopCapture();

    std::string getInterface() const;

private:
    static void packetCallback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet);

    pcap_t* handle_ = nullptr;
    std::string interface_;
    std::string filter_expr_;
};
