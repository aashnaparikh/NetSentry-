#include "logger/AlertLogger.h"

#include <iostream>
#include <sstream>

AlertLogger::AlertLogger(bool log_to_file, const std::string& filepath)
    : log_to_file_(log_to_file) {
    if (log_to_file_) {
        file_stream_.open(filepath, std::ios::app);
    }
}

AlertLogger::~AlertLogger() {
    if (file_stream_.is_open()) {
        file_stream_.close();
    }
}

std::string AlertLogger::severityToString(Severity s) {
    switch (s) {
        case Severity::INFO:
            return "INFO";
        case Severity::WARN:
            return "WARN";
        case Severity::CRITICAL:
            return "CRITICAL";
    }
    return "UNKNOWN";
}

void AlertLogger::log(Severity severity, const std::string& alert_type, const std::string& src_ip,
                        const std::string& details) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::time_t now = std::time(nullptr);
    char timestamp[32];
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&now));

    std::ostringstream oss;
    oss << "{"
        << "\"timestamp\":\"" << timestamp << "\","
        << "\"severity\":\"" << severityToString(severity) << "\","
        << "\"alert_type\":\"" << alert_type << "\","
        << "\"src_ip\":\"" << src_ip << "\","
        << "\"details\":\"" << details << "\""
        << "}";

    std::string line = oss.str();

    std::cout << line << std::flush << std::endl;

    if (log_to_file_ && file_stream_.is_open()) {
        file_stream_ << line << std::endl;
    }
}
