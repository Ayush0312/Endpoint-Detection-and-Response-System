#include <iostream>
#include <fstream>
#include <filesystem>
#include <thread>
#include <chrono>

namespace fs = std::filesystem;

int main() {
    try {
        std::cout << "Simple monitor starting...\n";
        std::cout << "Current directory: " << fs::current_path().string() << "\n";
        
        // Create a test file in the current directory
        std::ofstream testFile("test_monitor.txt");
        testFile << "Test content\n";
        testFile.close();
        
        std::cout << "Created test file: test_monitor.txt\n";
        std::cout << "Press Enter to exit...\n";
        std::cin.get();
        
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
} 