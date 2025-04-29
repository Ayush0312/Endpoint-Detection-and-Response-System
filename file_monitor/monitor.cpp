#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>
#include <ctime>
#include <vector>
#include <map>
#include <set>

// Function to get current timestamp
std::string get_timestamp() {
    time_t now = time(0);
    return ctime(&now);
}

int main() {
    std::cout << "[*] Starting file monitor...\n";
    
    // Open log file
    std::ofstream log("edr_log.txt");
    if (!log.is_open()) {
        std::cerr << "Failed to open log file\n";
        return 1;
    }
    
    // Get current directory
    char curDir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, curDir);
    std::cout << "[*] Current directory: " << curDir << "\n";
    log << "[*] Current directory: " << curDir << "\n";
    
    // Monitor folder path
    std::string monitorPath = "..\\test_monitor_folder";
    std::cout << "[*] Monitoring folder: " << monitorPath << "\n";
    log << "[*] Monitoring folder: " << monitorPath << "\n";
    
    // Main monitoring loop
    while (true) {
        Sleep(1000); // Check every second
        
        std::string timestamp = get_timestamp();
        log << "\n[*] Monitor active at: " << timestamp;
        std::cout << "\n[*] Monitor active at: " << timestamp;
        
        // Get current files
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA((monitorPath + "\\*.*").c_str(), &findData);
        
        std::set<std::string> files;
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                std::string filename = findData.cFileName;
                if (filename != "." && filename != "..") {
                    files.insert(monitorPath + "\\" + filename);
                }
            } while (FindNextFileA(hFind, &findData));
            FindClose(hFind);
        }
        
        // Log current files
        log << "[*] Current files in folder:\n";
        std::cout << "[*] Current files in folder:\n";
        for (const auto& file : files) {
            log << "    - " << file << "\n";
            std::cout << "    - " << file << "\n";
            
            // Get file timestamp
            HANDLE hFile = FindFirstFileA(file.c_str(), &findData);
            if (hFile != INVALID_HANDLE_VALUE) {
                FILETIME ftWrite = findData.ftLastWriteTime;
                SYSTEMTIME stUTC, stLocal;
                
                FileTimeToSystemTime(&ftWrite, &stUTC);
                SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);
                
                char buffer[80];
                sprintf(buffer, "%04d-%02d-%02d %02d:%02d:%02d",
                        stLocal.wYear, stLocal.wMonth, stLocal.wDay,
                        stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
                        
                log << "[*] " << file << ": " << buffer << "\n";
                std::cout << "[*] " << file << ": " << buffer << "\n";
                
                FindClose(hFile);
            }
        }
        
        log.flush();
    }
    
    return 0;
} 