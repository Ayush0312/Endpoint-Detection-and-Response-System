#include "monitor.h"
#include "file_utils.h"
#include "registry_utils.h"
#include "toast.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>
#include <thread>
#include <unordered_map>
#include <vector>
#include <windows.h>

using json = nlohmann::json;

void monitor_loop() {
    std::vector<std::string> files = {
        "C:\\Windows\\regedit.exe",
        "C:\\Windows\\System32\\userinit.exe",
        "C:\\Windows\\explorer.exe",
        "C:\\Windows\\system.ini",
        "C:\\Windows\\win.ini",
        "C:\\Windows\\System32\\config\\SYSTEM",
        "C:\\Windows\\System32\\config\\SOFTWARE",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\System32\\winlogon.exe",
        "C:\\Windows\\System32\\lsass.exe"
    };

    struct RegistryEntry {
        HKEY root;
        std::string subkey;
        std::vector<std::string> values;
    };

    std::vector<RegistryEntry> registryKeys = {
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", {"loadappinit_dlls", "appinit_dlls", "iconservicelib"} },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", {"common startup", "startup"} },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", {"common startup", "startup"} },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", {} },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", {} },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce", {} },
        { HKEY_LOCAL_MACHINE, "SECURITY\\POLICY\\SECRETS", {} },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\OID", {} },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\NT\\CurrentVersion\\Windows", {"appinit_dlls", "loadappinit_dlls"} },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", {"common startup", "startup"} },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", {"common startup", "startup"} },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", {} },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", {} }
    };

    std::unordered_map<std::string, std::string> previous_file_timestamps;
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> previous_registry_values;

    while (true) {
        try {
            json result;

            // File monitoring
            for (const auto& file : files) {
                std::string current_timestamp = get_file_timestamp(file);
                if (previous_file_timestamps[file] != current_timestamp) {
                    std::cout << "[*] File changed: " << file << " (New timestamp: " << current_timestamp << ")\n";
                    previous_file_timestamps[file] = current_timestamp;
                }
                result["files"][file] = {
                    {"last_modified", current_timestamp}
                };
            }

            // Registry monitoring
            for (const auto& entry : registryKeys) {
                json regData;
                if (!entry.values.empty()) {
                    for (const auto& val : entry.values) {
                        std::string current_value = read_registry_value(entry.root, entry.subkey, val);
                        if (previous_registry_values[entry.subkey][val] != current_value) {
                            std::cout << "[*] Registry changed: " << entry.subkey << "\\" << val << " (New value: " << current_value << ")\n";
                            previous_registry_values[entry.subkey][val] = current_value;
                        }
                        regData[val] = current_value;
                    }
                }
                else {
                    // Empty JSON object to ensure it's not null
                    regData = json::object();
                }
                result["registry"][entry.subkey] = regData;
            }

            // Write to JSON
            std::ofstream outFile("file_registry_monitor.json");
            outFile << result.dump(4);
            outFile.close();

            std::cout << "[✓] Updated JSON at " << get_current_timestamp() << "\n";

            show_toast_notification("File & Registry Monitor", "Snapshot saved successfully.");

            std::this_thread::sleep_for(std::chrono::minutes(1));
        }
        catch (const std::exception& e) {
            std::cerr << "Monitoring error: " << e.what() << "\n";
        }
    }
}