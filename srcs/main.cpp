#include <fstream>
#include <iostream>
#include <string>
#include <Windows.h>

#include "injector.h"

char *read_file(const char *path) {
    std::ifstream file(path, std::ios::binary);
    if (!file)
        return nullptr;

    file.seekg(0, std::ios::end);
    const std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    const auto buffer = new char[size];
    if (!file.read(buffer, size)) {
        delete[] buffer;
        return nullptr;
    }

    return buffer;
}

int main(const int argc, char **argv) {
    // Check program args.
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <process id> <dll path>" << std::endl;
        return 1;
    }

    // Parse PID.
    const DWORD process_id = std::stoul(argv[1]);
    if (process_id <= 0) {
        std::cout << "Invalid process id!" << std::endl;
        return 2;
    }

    // Read DLL.
    char *dll = read_file(argv[2]);
    if (dll == nullptr) {
        std::cerr << "Failed to read file" << std::endl;
        return 3;
    }

    manual_map(process_id, dll);
    free(dll);
    return 0;
}