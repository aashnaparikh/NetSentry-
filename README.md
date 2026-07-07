# NetSentry

A C++17 CLI tool that captures live network packets using libpcap, parses Ethernet/IP/TCP/UDP headers via manual struct parsing, and detects network anomalies (port scans, SYN floods, ARP spoofing) using sliding window counters. Outputs structured JSON alerts to stdout and a log file.

## Architecture

```
PacketCapture (libpcap) → EthernetParser → IPParser → TCPParser/UDPParser
                                    │
                                    ▼
                    PortScanDetector | SynFloodDetector | ARPDetector
                                    │
                                    ▼
                              AlertLogger (JSON → stdout + file)
```

## Skills demonstrated

- C++17: RAII, classes, std::optional, std::chrono, smart pointers, templates
- Network protocols: manual parsing of Ethernet/IP/TCP/UDP header structs
- Anomaly detection: sliding window counters with time-based expiry
- CMake: multi-target build with separate library and test executable
- GTest: unit tests with synthetic packet byte arrays, no live network required
- GitHub Actions: automated build + test on every push to main

## Build

```bash
# Install dependencies (Ubuntu/Debian)
./scripts/install_deps.sh

# Build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Run (requires root for libpcap)
sudo ./netsentry -i eth0
sudo ./netsentry -i eth0 -f "tcp" --port-threshold 20 -o alerts.log
```

## Example output

```
{"timestamp":"2026-07-07T21:53:00Z","severity":"CRITICAL","alert_type":"PORT_SCAN","src_ip":"192.168.1.105","details":"22 unique ports in 10s window"}
{"timestamp":"2026-07-07T21:53:01Z","severity":"CRITICAL","alert_type":"SYN_FLOOD","src_ip":"10.0.0.44","details":"147 SYNs in 5s window"}
{"timestamp":"2026-07-07T21:53:03Z","severity":"CRITICAL","alert_type":"ARP_SPOOF","src_ip":"192.168.1.1","details":"MAC changed from aa:bb:cc:dd:ee:ff to 11:22:33:44:55:66"}
```

## Testing

```bash
cd build && ctest --output-on-failure
```
