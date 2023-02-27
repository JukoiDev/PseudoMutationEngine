#pragma once

#include <vector>

class MemoryRegion {
public:
    MemoryRegion(void* address, size_t size);
    ~MemoryRegion();

    void* address() const;
    size_t size() const;

private:
    void* m_address;
    size_t m_size;
};

class MemoryScanner {
public:
    MemoryScanner(HMODULE module);

    std::vector<void*> scan(const char* pattern, const char* mask);

private:
    HMODULE m_module;
    char* m_startAddress;
    char* m_endAddress;
};

class MemoryInjector {
public:
    MemoryInjector();

    void inject(void* address, const void* code, size_t size);
    MemoryRegion allocate(size_t size);
};
