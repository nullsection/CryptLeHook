#include <iostream>
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "Crypt32.lib")

void PrintBytes(const BYTE* data, DWORD size) {
    for (DWORD i = 0; i < size; ++i) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

int main() {
    // Example data to protect and then unprotect
    MessageBoxA(NULL, "BEFORE", "BEGIN", MB_OK);
    BYTE data[] = "SensitiveData";
    DWORD dataSize = sizeof(data);

    // Ensure the data size is a multiple of 16 bytes
    DWORD paddedSize = ((dataSize + 15) / 16) * 16;  // Round up to the nearest multiple of 16
    BYTE* paddedData = new BYTE[paddedSize]();

    // Copy the original data to the padded buffer
    memcpy(paddedData, data, dataSize);

    std::cout << "Original Data: " << (char*)paddedData << std::endl;

    // Encrypt memory using CryptProtectMemory
    if (!CryptProtectMemory(paddedData, paddedSize, CRYPTPROTECTMEMORY_SAME_PROCESS)) {
        std::cerr << "Failed to protect memory. Error: " << GetLastError() << std::endl;
        delete[] paddedData;
        return 1;
    }

    std::cout << "Encrypted Data: ";
    PrintBytes(paddedData, paddedSize);

    // Decrypt memory using CryptUnprotectMemory
    if (!CryptUnprotectMemory(paddedData, paddedSize, CRYPTPROTECTMEMORY_SAME_PROCESS)) {
        std::cerr << "Failed to unprotect memory. Error: " << GetLastError() << std::endl;
        delete[] paddedData;
        return 1;
    }

    std::cout << "Decrypted Data: " << (char*)paddedData << std::endl;

    delete[] paddedData;  // Clean up allocated memory

    return 0;
}
