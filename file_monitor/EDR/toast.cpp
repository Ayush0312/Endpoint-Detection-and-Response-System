#include "toast.h"
#include <string>
#include <sstream>
#include <cstdlib>
#include <windows.h>
#include <fstream>

void show_toast_notification(const std::string& title, const std::string& message) {
    // Use MessageBox for notifications instead of toast
    MessageBoxA(NULL, message.c_str(), title.c_str(), MB_ICONINFORMATION | MB_SYSTEMMODAL);
    
    // Also log the notification
    std::ofstream logFile("edr_log.txt", std::ios::app);
    logFile << "[NOTIFICATION] " << title << ": " << message << std::endl;
}
