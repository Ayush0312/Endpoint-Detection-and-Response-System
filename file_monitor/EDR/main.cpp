#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>
#include <ctime>
#include <vector>
#include <map>
#include <set>
#include <shlobj.h>
#include <nlohmann/json.hpp>
#include "toast.h"
#include "registry_utils.h"
#include "file_utils.h"
#include <thread>

using json = nlohmann::json;

// Structure to store file information
struct FileInfo {
    std::string lastModified;
    bool exists;
    std::string filename;
    std::string hash;  // Added for file integrity checking
};

// Structure to store folder monitoring info
struct MonitorFolder {
    std::string path;
    std::string description;
    bool isActive;
};

// Structure to store registry monitoring info
struct RegistryMonitor {
    HKEY root;
    std::string subkey;
    std::vector<std::string> values;
    bool isActive;
};

// Function to get file information
FileInfo get_file_info(const std::string& path) {
    FileInfo info;
    info.filename = path;
    try {
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA(path.c_str(), &findData);
        
        if (hFind != INVALID_HANDLE_VALUE) {
            FindClose(hFind);
            
            // Get file timestamp using file_utils
            info.lastModified = get_file_timestamp(path);
            info.exists = true;
            
            // Calculate file hash (simplified version)
            std::ifstream file(path, std::ios::binary);
            if (file) {
                std::stringstream ss;
                ss << std::hex << std::hash<std::string>{}(path + info.lastModified);
                info.hash = ss.str();
            }
        } else {
            info.lastModified = "File not found";
            info.exists = false;
            std::cout << "[DEBUG] File not found: " << path << " (Error: " << GetLastError() << ")" << std::endl;
        }
    }
    catch (const std::exception& e) {
        info.lastModified = std::string("Error: ") + e.what();
        info.exists = false;
        std::cout << "[DEBUG] Exception while getting file info: " << e.what() << std::endl;
    }
    return info;
}

// Function to show alert
void show_alert(const std::string& message, const std::string& folder) {
    std::cout << "\n******************************************" << std::endl;
    std::cout << "*** ALERT! ALERT! ALERT! ***" << std::endl;
    std::cout << "*** Folder: " << folder << " ***" << std::endl;
    std::cout << "*** " << message << " ***" << std::endl;
    std::cout << "******************************************\n" << std::endl;
    
    // Show toast notification
    show_toast_notification("EDR Alert", message);
    
    // Make console beep twice for better notification
    Beep(1000, 500);
    Sleep(100);
    Beep(1000, 500);
}

// Function to get all files in a directory
std::set<std::string> get_directory_files(const std::string& folder) {
    std::set<std::string> files;
    std::string searchPath = folder + "\\*.*";
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
    
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::string filename = findData.cFileName;
            if (filename != "." && filename != "..") {
                std::string filePath = folder + "\\" + filename;
                
                // Check if it's a directory
                if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    // Recursively scan subdirectories
                    std::set<std::string> subFiles = get_directory_files(filePath);
                    files.insert(subFiles.begin(), subFiles.end());
                } else {
                    // It's a file, add it to the list
                    files.insert(filePath);
                }
            }
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    } else {
        DWORD error = GetLastError();
        std::cout << "[DEBUG] Error accessing directory: " << folder << " (Error: " << error << ")" << std::endl;
        
        // Log specific error messages
        switch (error) {
            case ERROR_ACCESS_DENIED:
                std::cout << "[DEBUG] Access denied to directory: " << folder << std::endl;
                break;
            case ERROR_PATH_NOT_FOUND:
                std::cout << "[DEBUG] Path not found: " << folder << std::endl;
                break;
            case ERROR_NOT_ENOUGH_MEMORY:
                std::cout << "[DEBUG] Not enough memory to access directory: " << folder << std::endl;
                break;
            default:
                std::cout << "[DEBUG] Unknown error accessing directory: " << folder << std::endl;
                break;
        }
    }
    return files;
}

// Function to check if folder is accessible
bool is_folder_accessible(const std::string& path) {
    DWORD attrs = GetFileAttributesA(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        DWORD error = GetLastError();
        std::cout << "[DEBUG] Cannot access folder: " << path << " (Error: " << error << ")" << std::endl;
        
        // Log specific error messages
        switch (error) {
            case ERROR_ACCESS_DENIED:
                std::cout << "[DEBUG] Access denied to folder: " << path << std::endl;
                break;
            case ERROR_PATH_NOT_FOUND:
                std::cout << "[DEBUG] Path not found: " << path << std::endl;
                break;
            case ERROR_NOT_ENOUGH_MEMORY:
                std::cout << "[DEBUG] Not enough memory to access folder: " << path << std::endl;
                break;
            default:
                std::cout << "[DEBUG] Unknown error accessing folder: " << path << std::endl;
                break;
        }
        return false;
    }
    return (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

// Function to get system folders
std::vector<MonitorFolder> get_system_folders() {
    std::vector<MonitorFolder> folders;
    
    // Get Desktop path directly using SHGetFolderPath
    char desktopPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, desktopPath))) {
        if (is_folder_accessible(desktopPath)) {
            folders.push_back({desktopPath, "Desktop", true});
            std::cout << "[*] Added Desktop folder: " << desktopPath << std::endl;
        } else {
            std::cout << "[!] Warning: Cannot access Desktop folder: " << desktopPath << std::endl;
        }
    }
    
    // Get Documents path
    char documentsPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, 0, documentsPath))) {
        if (is_folder_accessible(documentsPath)) {
            folders.push_back({documentsPath, "Documents", true});
            std::cout << "[*] Added Documents folder: " << documentsPath << std::endl;
        }
    }
    
    // Get Downloads path (using user profile)
    char userProfile[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, userProfile))) {
        std::string downloadsPath = std::string(userProfile) + "\\Downloads";
        if (is_folder_accessible(downloadsPath)) {
            folders.push_back({downloadsPath, "Downloads", true});
            std::cout << "[*] Added Downloads folder: " << downloadsPath << std::endl;
        }
    }
    
    // Add system folders
    std::vector<std::string> systemFolders = {
        "C:\\Windows\\System32",
        "C:\\Windows\\System",
        "C:\\Program Files",
        "C:\\Program Files (x86)",
        "C:\\Users\\Public"
    };
    
    for (const auto& folder : systemFolders) {
        if (is_folder_accessible(folder)) {
            folders.push_back({folder, "System", true});
            std::cout << "[*] Added system folder: " << folder << std::endl;
        } else {
            std::cout << "[!] Warning: Cannot access system folder: " << folder << std::endl;
        }
    }
    
    return folders;
}

// Function to get registry monitors
std::vector<RegistryMonitor> get_registry_monitors() {
    std::vector<RegistryMonitor> monitors = {
        { HKEY_CURRENT_USER, "Software\\EDRTest", {"TestValue"}, true },  // Test registry key first
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", 
          {"loadappinit_dlls", "appinit_dlls", "iconservicelib"}, true },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", 
          {"common startup", "startup"}, true },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", {}, true },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", {}, true }
    };
    return monitors;
}

int main() {
    try {
        // Open log file with error checking
        std::ofstream logFile("edr_log.txt", std::ios::app);
        if (!logFile.is_open()) {
            std::cerr << "Error: Could not open log file!" << std::endl;
            return 1;
        }
        
        // Print to both console and file
        std::cout << "[*] Starting EDR monitor..." << std::endl;
        logFile << "[*] Starting EDR monitor..." << std::endl;
        logFile.flush();
        
        // Get current directory
        char currentDir[MAX_PATH];
        if (GetCurrentDirectoryA(MAX_PATH, currentDir) == 0) {
            std::cerr << "Error: Could not get current directory!" << std::endl;
            logFile << "Error: Could not get current directory!" << std::endl;
            return 1;
        }
        
        std::cout << "[*] Current directory: " << currentDir << std::endl;
        logFile << "[*] Current directory: " << currentDir << std::endl;
        logFile.flush();
        
        // Get folders to monitor
        std::cout << "\n[*] Initializing folder monitoring..." << std::endl;
        std::vector<MonitorFolder> folders = get_system_folders();
        
        if (folders.empty()) {
            std::cerr << "Error: No accessible folders to monitor!" << std::endl;
            logFile << "Error: No accessible folders to monitor!" << std::endl;
            return 1;
        }
        
        // Get registry monitors
        std::vector<RegistryMonitor> registryMonitors = get_registry_monitors();
        
        std::cout << "\n[*] Successfully initialized " << folders.size() << " folders and " 
                  << registryMonitors.size() << " registry keys for monitoring" << std::endl;
        
        // Store previous states
        std::map<std::string, std::map<std::string, FileInfo>> previousFileStates;
        std::map<std::string, std::map<std::string, std::string>> previousRegistryStates;
        
        // Initialize previous states
        for (const auto& folder : folders) {
            if (folder.isActive) {
                std::cout << "[*] Initializing monitoring for: " << folder.path << std::endl;
                logFile << "[*] Initializing monitoring for: " << folder.path << std::endl;
                
                std::set<std::string> initialFiles = get_directory_files(folder.path);
                std::cout << "[*] Found " << initialFiles.size() << " files in " << folder.path << std::endl;
                
                for (const auto& path : initialFiles) {
                    previousFileStates[folder.path][path] = get_file_info(path);
                }
            }
        }
        
        // Initialize registry states and start monitoring threads
        std::vector<std::thread> registry_threads;
        for (const auto& monitor : registryMonitors) {
            if (monitor.isActive) {
                for (const auto& value : monitor.values) {
                    std::string currentValue = read_registry_value(monitor.root, monitor.subkey, value);
                    previousRegistryStates[monitor.subkey][value] = currentValue;
                    
                    // Start a monitoring thread for this registry value
                    registry_threads.emplace_back(monitor_registry_changes, monitor.root, monitor.subkey, value, std::ref(logFile));
                }
            }
        }
        
        std::cout << "[*] Initial states captured. Starting monitoring..." << std::endl;
        logFile << "[*] Initial states captured. Starting monitoring..." << std::endl;
        
        // Keep the program running
        while (true) {
            Sleep(1000); // Sleep for 1 second
            
            // Log the start of each monitoring cycle
            logFile << "[DEBUG] Starting monitoring cycle at " << get_current_timestamp() << std::endl;
            
            // Check if log file is still valid
            if (!logFile.is_open()) {
                std::cerr << "Error: Log file is no longer open!" << std::endl;
                logFile.open("edr_log.txt", std::ios::app);
                if (!logFile.is_open()) {
                    std::cerr << "Error: Could not reopen log file!" << std::endl;
                    return 1;
                }
                logFile << "[*] Log file reopened at " << get_current_timestamp() << std::endl;
            }
            
            // Monitor folders
            for (const auto& folder : folders) {
                if (!folder.isActive) {
                    logFile << "[DEBUG] Skipping inactive folder: " << folder.path << std::endl;
                    continue;
                }
                
                logFile << "[DEBUG] Checking folder: " << folder.path << std::endl;
                std::set<std::string> currentFiles = get_directory_files(folder.path);
                logFile << "[DEBUG] Found " << currentFiles.size() << " files in " << folder.path << std::endl;
                
                // Check for new or modified files
                for (const auto& path : currentFiles) {
                    FileInfo currentInfo = get_file_info(path);
                    if (previousFileStates[folder.path].find(path) == previousFileStates[folder.path].end()) {
                        // New file
                        logFile << "[ALERT] New file detected: " << path << std::endl;
                        show_alert("New file detected: " + path, folder.path);
                    } else {
                        // Check if file was modified
                        const FileInfo& prevInfo = previousFileStates[folder.path][path];
                        if (currentInfo.lastModified != prevInfo.lastModified || currentInfo.hash != prevInfo.hash) {
                            logFile << "[ALERT] File modified: " << path << std::endl;
                            show_alert("File modified: " + path, folder.path);
                        }
                    }
                    previousFileStates[folder.path][path] = currentInfo;
                }
                
                // Check for deleted files
                for (const auto& prevFile : previousFileStates[folder.path]) {
                    if (currentFiles.find(prevFile.first) == currentFiles.end()) {
                        logFile << "[ALERT] File deleted: " << prevFile.first << std::endl;
                        show_alert("File deleted: " + prevFile.first, folder.path);
                        previousFileStates[folder.path].erase(prevFile.first);
                    }
                }
            }
            
            // Generate JSON report
            logFile << "[DEBUG] Starting JSON report generation" << std::endl;
            try {
                json report;
                report["timestamp"] = get_current_timestamp();
                report["monitor_status"] = "active";
                
                // Add file information
                logFile << "[DEBUG] Adding file information to JSON report" << std::endl;
                for (const auto& folder : folders) {
                    if (!folder.isActive) {
                        logFile << "[DEBUG] Skipping inactive folder: " << folder.path << std::endl;
                        continue;
                    }
                    
                    json folderData;
                    for (const auto& file : previousFileStates[folder.path]) {
                        folderData[file.first] = {
                            {"last_modified", file.second.lastModified},
                            {"exists", file.second.exists},
                            {"hash", file.second.hash}
                        };
                    }
                    report["files"][folder.path] = folderData;
                }
                
                // Add registry information
                logFile << "[DEBUG] Adding registry information to JSON report" << std::endl;
                for (const auto& monitor : registryMonitors) {
                    if (!monitor.isActive) {
                        logFile << "[DEBUG] Skipping inactive registry monitor in JSON: " << monitor.subkey << std::endl;
                        continue;
                    }
                    
                    json regData;
                    for (const auto& value : monitor.values) {
                        std::string currentValue = read_registry_value(monitor.root, monitor.subkey, value);
                        regData[value] = currentValue;
                    }
                    report["registry"][monitor.subkey] = regData;
                }
                
                // Write JSON report
                std::string jsonPath = "edr_report.json";
                logFile << "[DEBUG] Writing JSON report to: " << jsonPath << std::endl;
                std::ofstream jsonFile(jsonPath);
                if (jsonFile.is_open()) {
                    jsonFile << report.dump(4);
                    jsonFile.close();
                    logFile << "[*] JSON report generated at " << get_current_timestamp() << std::endl;
                } else {
                    std::cerr << "[!] Error: Could not open JSON report file for writing: " << jsonPath << std::endl;
                    logFile << "[!] Error: Could not open JSON report file for writing: " << jsonPath << std::endl;
                }
            } catch (const std::exception& e) {
                std::cerr << "[!] Error generating JSON report: " << e.what() << std::endl;
                logFile << "[!] Error generating JSON report: " << e.what() << std::endl;
            }
            
            logFile << "[DEBUG] Completed monitoring cycle" << std::endl;
            logFile.flush();
        }
        
        // Cleanup
        g_monitoring_active = false;
        for (auto& thread : registry_threads) {
            if (thread.joinable()) {
                thread.join();
            }
        }
        
        return 0;
    }
    catch (const std::exception& e) {
        std::ofstream errorLog("error_log.txt", std::ios::app);
        errorLog << "Error: " << e.what() << std::endl;
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
