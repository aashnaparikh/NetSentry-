#pragma once

#include <string>
#include <fstream>
#include <mutex>
#include <ctime>

enum class Severity { INFO, WARN, CRITICAL };

// Thread-safe structured JSON alert logger. Writes one JSON object per
// line to stdout, and optionally appends to a log file.
class AlertLogger {
public:
    explicit AlertLogger(bool log_to_file = false, const std::string& filepath = "netsentry.log");
    ~AlertLogger();

    void log(Severity severity, const std::string& alert_type, const std::string& src_ip,
              const std::string& details);

    static std::string severityToString(Severity s);

private:
    std::mutex mutex_;
    std::ofstream file_stream_;
    bool log_to_file_;
};
