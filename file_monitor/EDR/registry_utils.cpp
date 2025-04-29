#include "registry_utils.h"
#include <windows.h>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include <atomic>

// Global flag to indicate if monitoring should continue
std::atomic<bool> g_monitoring_active(true);

// Function to monitor registry changes
void monitor_registry_changes(HKEY root, const std::string& subKey, const std::string& valueName, std::ofstream& logFile) {
    HKEY hKey;
    DWORD filter = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_ATTRIBUTES | 
                  REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_SECURITY;
    
    // Open the registry key
    LONG result = RegOpenKeyExA(root, subKey.c_str(), 0, KEY_NOTIFY, &hKey);
    if (result != ERROR_SUCCESS) {
        logFile << "[ERROR] Failed to open registry key for monitoring: " << subKey << " (Error: " << result << ")" << std::endl;
        return;
    }
    
    // Create an event for notification
    HANDLE hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (hEvent == NULL) {
        logFile << "[ERROR] Failed to create event for registry monitoring" << std::endl;
        RegCloseKey(hKey);
        return;
    }
    
    // Start monitoring
    while (g_monitoring_active) {
        // Request notification
        result = RegNotifyChangeKeyValue(hKey, TRUE, filter, hEvent, TRUE);
        if (result != ERROR_SUCCESS) {
            logFile << "[ERROR] Failed to set registry notification: " << result << std::endl;
            break;
        }
        
        // Wait for notification
        DWORD waitResult = WaitForSingleObject(hEvent, 1000); // 1 second timeout
        if (waitResult == WAIT_OBJECT_0) {
            // Check if the value has changed
            std::string currentValue = read_registry_value(root, subKey, valueName);
            logFile << "[DEBUG] Registry change detected for: " << subKey << "\\" << valueName 
                   << " - New value: " << currentValue << std::endl;
            
            // Reset the event
            ResetEvent(hEvent);
        }
    }
    
    // Cleanup
    CloseHandle(hEvent);
    RegCloseKey(hKey);
}

std::string read_registry_value(HKEY root, const std::string& subKey, const std::string& valueName) {
    try {
        HKEY hKey;
        char value[1024] = {0};  // Initialize to zero
        DWORD value_length = sizeof(value);
        DWORD type = 0;

        // Log the attempt to read the registry value
        std::ofstream logFile("edr_log.txt", std::ios::app);
        logFile << "[DEBUG] Attempting to read registry value: " << subKey << "\\" << valueName << std::endl;

        // First try to open the key
        LONG result = RegOpenKeyExA(root, subKey.c_str(), 0, KEY_READ, &hKey);
        if (result != ERROR_SUCCESS) {
            logFile << "[ERROR] Failed to open registry key: " << subKey << " (Error: " << result << ")" << std::endl;
            return "N/A";
        }

        // Get the value type and size first
        result = RegQueryValueExA(hKey, valueName.c_str(), nullptr, &type, nullptr, &value_length);
        if (result != ERROR_SUCCESS) {
            logFile << "[ERROR] Failed to get registry value info: " << subKey << "\\" << valueName << " (Error: " << result << ")" << std::endl;
            RegCloseKey(hKey);
            return "N/A";
        }

        // Now read the actual value
        result = RegQueryValueExA(hKey, valueName.c_str(), nullptr, &type, reinterpret_cast<LPBYTE>(value), &value_length);
        if (result != ERROR_SUCCESS) {
            logFile << "[ERROR] Failed to read registry value: " << subKey << "\\" << valueName << " (Error: " << result << ")" << std::endl;
            RegCloseKey(hKey);
            return "N/A";
        }

        RegCloseKey(hKey);

        // Handle different registry value types
        std::string result_str;
        switch (type) {
            case REG_SZ:
            case REG_EXPAND_SZ:
                result_str = std::string(value, value + value_length);
                break;
            case REG_DWORD:
                result_str = std::to_string(*reinterpret_cast<DWORD*>(value));
                break;
            case REG_QWORD:
                result_str = std::to_string(*reinterpret_cast<QWORD*>(value));
                break;
            case REG_MULTI_SZ: {
                std::stringstream ss;
                char* p = value;
                while (*p) {
                    if (!ss.str().empty()) ss << ", ";
                    ss << p;
                    p += strlen(p) + 1;
                }
                result_str = ss.str();
                break;
            }
            default:
                logFile << "[WARNING] Unsupported registry value type: " << type << " for " << subKey << "\\" << valueName << std::endl;
                return "N/A";
        }

        logFile << "[DEBUG] Successfully read registry value: " << subKey << "\\" << valueName << " = " << result_str << std::endl;
        return result_str;
    }
    catch (const std::exception& e) {
        std::ofstream logFile("edr_log.txt", std::ios::app);
        logFile << "[ERROR] Exception while reading registry: " << e.what() << std::endl;
        return "N/A";
    }
    catch (...) {
        std::ofstream logFile("edr_log.txt", std::ios::app);
        logFile << "[ERROR] Unknown exception while reading registry" << std::endl;
        return "N/A";
    }
}
