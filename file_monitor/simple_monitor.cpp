#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>
#include <ctime>
#include <vector>
#include <map>
#include <set>
#include <shlobj.h>

// Structure to store file information
struct FileInfo {
    std::string lastModified;
    bool exists;
};

// Get current timestamp as string
std::string get_current_timestamp() {
    time_t now = time(0);
    return ctime(&now);
}

// Function to get file timestamp
std::string get_file_timestamp(const std::string& path) {
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(path.c_str(), &findData);
    
    if (hFind != INVALID_HANDLE_VALUE) {
        FindClose(hFind);
        FILETIME ftWrite = findData.ftLastWriteTime;
        SYSTEMTIME stUTC, stLocal;
        
        FileTimeToSystemTime(&ftWrite, &stUTC);
        SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);
        
        char buffer[80];
        sprintf(buffer, "%04d-%02d-%02d %02d:%02d:%02d",
                stLocal.wYear, stLocal.wMonth, stLocal.wDay,
                stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
        return std::string(buffer);
    }
    return "File not found";
}

// Function to get file information
FileInfo get_file_info(const std::string& path) {
    FileInfo info;
    try {
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA(path.c_str(), &findData);
        
        if (hFind != INVALID_HANDLE_VALUE) {
            FindClose(hFind);
            info.lastModified = get_file_timestamp(path);
            info.exists = true;
        } else {
            info.lastModified = "File not found";
            info.exists = false;
        }
    }
    catch (const std::exception& e) {
        info.lastModified = std::string("Error: ") + e.what();
        info.exists = false;
    }
    return info;
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
                if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    files.insert(filePath);
                }
            }
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    }
    return files;
}

int main() {
    try {
        // Open log file
        std::ofstream logFile("edr_log.txt");
        if (!logFile.is_open()) {
            std::cerr << "Error: Could not open log file!" << std::endl;
            return 1;
        }
        
        // Get current directory
        char currentDir[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, currentDir);
        
        std::cout << "[*] Starting EDR monitor..." << std::endl;
        logFile << "[*] Starting EDR monitor..." << std::endl;
        
        std::cout << "[*] Current directory: " << currentDir << std::endl;
        logFile << "[*] Current directory: " << currentDir << std::endl;
        
        // Monitor test folder
        std::string monitorFolder = "..\\test_monitor_folder";
        std::cout << "[*] Monitoring folder: " << monitorFolder << std::endl;
        logFile << "[*] Monitoring folder: " << monitorFolder << std::endl;
        
        // Store previous state
        std::map<std::string, FileInfo> previousState;
        std::set<std::string> initialFiles = get_directory_files(monitorFolder);
        
        for (const auto& path : initialFiles) {
            previousState[path] = get_file_info(path);
        }
        
        std::cout << "[*] Initial file state captured. Starting monitoring..." << std::endl;
        logFile << "[*] Initial file state captured. Starting monitoring..." << std::endl;
        
        // Monitor loop
        while (true) {
            Sleep(1000); // Check every second
            
            time_t now = time(0);
            logFile << "\n[*] Monitor active at: " << ctime(&now);
            std::cout << "\n[*] Monitor active at: " << ctime(&now);
            
            // Get current files
            std::set<std::string> currentFiles = get_directory_files(monitorFolder);
            
            // Log current files
            logFile << "[*] Current files in folder:" << std::endl;
            std::cout << "[*] Current files in folder:" << std::endl;
            for (const auto& file : currentFiles) {
                logFile << "    - " << file << std::endl;
                std::cout << "    - " << file << std::endl;
            }
            
            // Check for new or modified files
            for (const auto& path : currentFiles) {
                FileInfo currentInfo = get_file_info(path);
                if (previousState.find(path) == previousState.end()) {
                    // New file
                    logFile << "[ALERT] New file detected: " << path << std::endl;
                    std::cout << "[ALERT] New file detected: " << path << std::endl;
                } else if (currentInfo.lastModified != previousState[path].lastModified) {
                    // Modified file
                    logFile << "[ALERT] File modified: " << path << std::endl;
                    std::cout << "[ALERT] File modified: " << path << std::endl;
                }
                previousState[path] = currentInfo;
            }
            
            // Check for deleted files
            for (const auto& prevFile : previousState) {
                if (currentFiles.find(prevFile.first) == currentFiles.end()) {
                    logFile << "[ALERT] File deleted: " << prevFile.first << std::endl;
                    std::cout << "[ALERT] File deleted: " << prevFile.first << std::endl;
                }
            }
            
            // Log file timestamps
            for (const auto& file : currentFiles) {
                FileInfo info = get_file_info(file);
                logFile << "[*] " << file << ": " << info.lastModified << std::endl;
                std::cout << "[*] " << file << ": " << info.lastModified << std::endl;
            }
            
            logFile.flush();
        }
        
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
} 