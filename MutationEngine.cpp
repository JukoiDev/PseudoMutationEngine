/*
 * TODO:
 * [ ] Proper testing
 * [ ] Implement XORing of the Strings
 * [ ] Polymorphism by adding random amounts of random instructions
 *
 * Please give credit if you are using this
*/

#include "MutationEngine.hpp"

#include <iostream>
#include <Windows.h>
#include <vector>

class MemoryRegion {
public:
    MemoryRegion(void* address, size_t size) : m_address(address), m_size(size) {}
    ~MemoryRegion() { VirtualFree(m_address, 0, MEM_RELEASE); }

    void* address() const { return m_address; }
    size_t size() const { return m_size; }

private:
    void* m_address;
    size_t m_size;
};

class MemoryScanner {
public:
    MemoryScanner(HMODULE module) : m_module(module) {
        MODULEINFO moduleInfo;
        GetModuleInformation(GetCurrentProcess(), m_module, &moduleInfo, sizeof(moduleInfo));
        m_startAddress = reinterpret_cast<char*>(moduleInfo.lpBaseOfDll);
        m_endAddress = m_startAddress + moduleInfo.SizeOfImage;
    }

    std::vector<void*> scan(const char* pattern, const char* mask) {
        std::vector<void*> results;
        int patternLength = strlen(mask);

        for (char* p = m_startAddress; p < m_endAddress - patternLength; ++p) {
            bool found = true;

            for (int i = 0; i < patternLength; ++i) {
                if (mask[i] != '?' && pattern[i] != p[i]) {
                    found = false;
                    break;
                }
            }

            if (found) {
                results.push_back(reinterpret_cast<void*>(p));
            }
        }

        return results;
    }

private:
    HMODULE m_module;
    char* m_startAddress;
    char* m_endAddress;
};

class MemoryInjector {
public:
    MemoryInjector() {}

    void inject(void* address, const void* code, size_t size) {
        DWORD oldProtect;
        VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(address, code, size);
        VirtualProtect(address, size, oldProtect, &oldProtect);
    }

    MemoryRegion allocate(size_t size) {
        // Allocate the address
        void* address = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        // Create the MemoryRegion object
        return MemoryRegion(address, size);
    }
};

int main() {
    // Get handle to this process
    HANDLE hProcess = GetCurrentProcess();

    // Get the base address of this module
    HMODULE baseAddress = GetModuleHandle(NULL);

    // Define the pattern and mask for the instruction we want to modify
    const char instructionPattern[] = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08 }; // THIS
    const char instructionMask[] = { 'x', 'x', 'x', 'x', 'x', 'x' }; // THIS
    // Scan for the address of the instruction to modify
    MemoryScanner scanner(baseAddress);
    std::vector<void*> results = scanner.scan(instructionPattern, instructionMask);
    if (!results.empty()) {
        // Inject the code
        const unsigned char newInstruction[] = { 0x90 }; // NOP instruction
        MemoryInjector injector;
        injector.inject(results[0], newInstruction, sizeof(newInstruction));

        // Execute the modified instruction
        std::cout << "Hello, world!" << std::endl;
    } else {
        std::cerr << "Could not find instruction to modify." << std::endl;
    }

    return 0;
}
