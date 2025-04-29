#include <fstream>

int main() {
    std::ofstream outFile("test_output.txt");
    outFile << "Test program running..." << std::endl;
    outFile << "This should appear in the file." << std::endl;
    outFile.close();
    return 0;
} 