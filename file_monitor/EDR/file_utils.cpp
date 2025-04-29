#include "file_utils.h"
#include <iostream>
#include <filesystem>
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>

namespace fs = std::filesystem;

std::string get_file_timestamp(const std::string& path) {
    try {
        if (!fs::exists(path)) {
            std::cerr << "[!] File does not exist: " << path << "\n";
            return "N/A";
        }

        auto ftime = fs::last_write_time(path);
        auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
            ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now()
        );
        std::time_t cftime = std::chrono::system_clock::to_time_t(sctp);

        std::tm timeinfo;
        if (localtime_s(&timeinfo, &cftime) != 0) {
            std::cerr << "[!] Failed to convert timestamp for: " << path << "\n";
            return "N/A";
        }

        std::stringstream ss;
        ss << std::put_time(&timeinfo, "%F %T");
        return ss.str();
    }
    catch (const std::exception& e) {
        std::cerr << "[!] Error reading timestamp for " << path << ": " << e.what() << "\n";
        return "N/A";
    }
}

std::string get_current_timestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::tm timeinfo;
    if (localtime_s(&timeinfo, &now_time) != 0) {
        std::cerr << "[!] Failed to get current local time.\n";
        return "N/A";
    }

    std::stringstream ss;
    ss << std::put_time(&timeinfo, "%F %T");
    return ss.str();
}
