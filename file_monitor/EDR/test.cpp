#include <iostream>
#include <windows.h>

int main() {
    try {
        std::cout << "Test program starting...\n";
        std::cout << "Current directory: " << GetCurrentDirectoryA(0, nullptr) << "\n";
        std::cout << "Press Enter to exit...\n";
        std::cin.get();
        return 0;
    }
    catch (...) {
        std::cerr << "Error occurred\n";
        return 1;
    }
} 