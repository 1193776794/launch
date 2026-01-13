#include "integrity_detector.h"
#include <android/log.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <elf.h>
#include <dlfcn.h>
#include <sstream>
#include <fstream>
#include <cstring>
#include <errno.h>
#include <cstdarg>

// Syscall numbers for Android
#ifndef __NR_openat
#define __NR_openat 56
#endif
#ifndef __NR_read
#define __NR_read 63
#endif
#ifndef __NR_close
#define __NR_close 57
#endif
#ifndef __NR_fstat
#if defined(__aarch64__)
#define __NR_fstat 80
#else
#define __NR_fstat 108
#endif
#endif

// Syscall wrapper
static inline long syscall_wrapper(long number, ...) {
    va_list args;
    va_start(args, number);
    long arg0 = va_arg(args, long);
    long arg1 = va_arg(args, long);
    long arg2 = va_arg(args, long);
    long arg3 = va_arg(args, long);
    long arg4 = va_arg(args, long);
    long arg5 = va_arg(args, long);
    va_end(args);
    return syscall(number, arg0, arg1, arg2, arg3, arg4, arg5);
}

#define LOG_TAG "IntegrityDetector"
#define LOGD(...) __android_log_print(3, LOG_TAG, __VA_ARGS__)  // ANDROID_LOG_DEBUG = 3
#define LOGW(...) __android_log_print(5, LOG_TAG, __VA_ARGS__)  // ANDROID_LOG_WARN = 5
#define LOGE(...) __android_log_print(6, LOG_TAG, __VA_ARGS__)  // ANDROID_LOG_ERROR = 6

// Critical functions to monitor
const char* IntegrityDetector::CRITICAL_LIBC_FUNCTIONS[] = {
    "open", "openat", "read", "write", "access", "faccessat",
    "stat", "fstat", "lstat", "readlink", "fopen", "fread",
    "__system_property_get", "getprop", nullptr
};

const char* IntegrityDetector::CRITICAL_LIBART_FUNCTIONS[] = {
    "_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc", // ArtMethod::Invoke
    "_ZN3art11ClassLinker17RegisterDexFileERKNS_7DexFileE",     // ClassLinker::RegisterDexFile
    nullptr
};

// CRC32 lookup table
static const uint32_t crc32_table[256] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

uint32_t IntegrityDetector::calculateCRC32(const uint8_t* data, size_t size) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < size; i++) {
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;
}

uintptr_t IntegrityDetector::findLibraryBase(const std::string& lib_name) {
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) {
        LOGE("Failed to open /proc/self/maps");
        return 0;
    }

    std::string line;
    while (std::getline(maps, line)) {
        if (line.find(lib_name) != std::string::npos) {
            // Parse address range: "70a1f3d000-70a1f45000 r-xp ..."
            uintptr_t start;
            if (sscanf(line.c_str(), "%lx", &start) == 1) {
                // Check if this is executable segment
                if (line.find(" r-xp ") != std::string::npos ||
                    line.find(" r--p ") != std::string::npos) {
                    LOGD("Found %s at base: 0x%lx", lib_name.c_str(), start);
                    return start;
                }
            }
        }
    }

    LOGW("Library %s not found in memory", lib_name.c_str());
    return 0;
}

std::string IntegrityDetector::getLibraryPath(const std::string& lib_name) {
    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return "";

    std::string line;
    while (std::getline(maps, line)) {
        if (line.find(lib_name) != std::string::npos) {
            // Extract path from: "address-address perm offset dev:inode /path/to/lib.so"
            size_t pathStart = line.rfind(' ');
            if (pathStart != std::string::npos && pathStart < line.length() - 1) {
                std::string path = line.substr(pathStart + 1);
                // Verify it's a valid path
                if (path[0] == '/' && path.find(".so") != std::string::npos) {
                    LOGD("Found library path: %s", path.c_str());
                    return path;
                }
            }
        }
    }

    return "";
}

std::vector<uint8_t> IntegrityDetector::readLibraryFile(const std::string& path) {
    std::vector<uint8_t> data;

    // Use direct syscall to avoid hooks
    int fd = syscall_wrapper(__NR_openat, AT_FDCWD, path.c_str(), O_RDONLY, 0);
    if (fd < 0) {
        LOGE("Failed to open %s: errno=%d", path.c_str(), errno);
        return data;
    }

    // Get file size
    struct stat st;
    if (syscall_wrapper(__NR_fstat, fd, &st) < 0) {
        LOGE("Failed to stat %s", path.c_str());
        syscall_wrapper(__NR_close, fd);
        return data;
    }

    size_t file_size = st.st_size;
    LOGD("Reading library file: %s (size: %zu bytes)", path.c_str(), file_size);

    // Limit to reasonable size (e.g., 10MB)
    if (file_size > 10 * 1024 * 1024) {
        LOGW("Library file too large: %zu bytes, limiting to 10MB", file_size);
        file_size = 10 * 1024 * 1024;
    }

    data.resize(file_size);

    // Read in chunks
    size_t total_read = 0;
    while (total_read < file_size) {
        ssize_t n = syscall_wrapper(__NR_read, fd, data.data() + total_read,
                                    file_size - total_read);
        if (n <= 0) break;
        total_read += n;
    }

    syscall_wrapper(__NR_close, fd);

    if (total_read != file_size) {
        LOGW("Partial read: %zu/%zu bytes", total_read, file_size);
        data.resize(total_read);
    }

    LOGD("Successfully read %zu bytes from %s", data.size(), path.c_str());
    return data;
}

bool IntegrityDetector::parseElfAndFindTextSection(const std::vector<uint8_t>& elf_data,
                                                   size_t& text_offset,
                                                   size_t& text_size) {
    if (elf_data.size() < sizeof(Elf64_Ehdr)) {
        LOGE("ELF data too small");
        return false;
    }

    // Check ELF magic
    if (elf_data[0] != 0x7f || elf_data[1] != 'E' ||
        elf_data[2] != 'L' || elf_data[3] != 'F') {
        LOGE("Invalid ELF magic");
        return false;
    }

    // Check if 32-bit or 64-bit
    bool is_64bit = (elf_data[4] == 2);

    if (is_64bit) {
        // 64-bit ELF
        const Elf64_Ehdr* ehdr = reinterpret_cast<const Elf64_Ehdr*>(elf_data.data());

        // Parse section headers
        for (int i = 0; i < ehdr->e_shnum; i++) {
            size_t sh_offset = ehdr->e_shoff + i * ehdr->e_shentsize;
            if (sh_offset + sizeof(Elf64_Shdr) > elf_data.size()) break;

            const Elf64_Shdr* shdr = reinterpret_cast<const Elf64_Shdr*>(
                elf_data.data() + sh_offset);

            // Get section name
            size_t name_offset = ehdr->e_shoff + ehdr->e_shstrndx * ehdr->e_shentsize;
            if (name_offset + sizeof(Elf64_Shdr) > elf_data.size()) continue;

            const Elf64_Shdr* strtab_shdr = reinterpret_cast<const Elf64_Shdr*>(
                elf_data.data() + name_offset);

            if (shdr->sh_name < strtab_shdr->sh_size) {
                const char* section_name = reinterpret_cast<const char*>(
                    elf_data.data() + strtab_shdr->sh_offset + shdr->sh_name);

                if (strcmp(section_name, ".text") == 0) {
                    text_offset = shdr->sh_offset;
                    text_size = shdr->sh_size;
                    LOGD("Found .text section: offset=0x%zx, size=0x%zx",
                         text_offset, text_size);
                    return true;
                }
            }
        }
    } else {
        // 32-bit ELF
        const Elf32_Ehdr* ehdr = reinterpret_cast<const Elf32_Ehdr*>(elf_data.data());

        for (int i = 0; i < ehdr->e_shnum; i++) {
            size_t sh_offset = ehdr->e_shoff + i * ehdr->e_shentsize;
            if (sh_offset + sizeof(Elf32_Shdr) > elf_data.size()) break;

            const Elf32_Shdr* shdr = reinterpret_cast<const Elf32_Shdr*>(
                elf_data.data() + sh_offset);

            size_t name_offset = ehdr->e_shoff + ehdr->e_shstrndx * ehdr->e_shentsize;
            if (name_offset + sizeof(Elf32_Shdr) > elf_data.size()) continue;

            const Elf32_Shdr* strtab_shdr = reinterpret_cast<const Elf32_Shdr*>(
                elf_data.data() + name_offset);

            if (shdr->sh_name < strtab_shdr->sh_size) {
                const char* section_name = reinterpret_cast<const char*>(
                    elf_data.data() + strtab_shdr->sh_offset + shdr->sh_name);

                if (strcmp(section_name, ".text") == 0) {
                    text_offset = shdr->sh_offset;
                    text_size = shdr->sh_size;
                    LOGD("Found .text section (32-bit): offset=0x%zx, size=0x%zx",
                         text_offset, text_size);
                    return true;
                }
            }
        }
    }

    LOGE("Failed to find .text section");
    return false;
}

bool IntegrityDetector::compareTextSections(uintptr_t mem_base,
                                           const std::vector<uint8_t>& disk_data,
                                           size_t text_offset,
                                           size_t text_size) {
    if (text_offset + text_size > disk_data.size()) {
        LOGE("Invalid .text section bounds");
        return false;
    }

    // Sample comparison - check first 4KB and last 4KB of .text
    // Full comparison would be too slow for large libraries
    const size_t SAMPLE_SIZE = 4096;
    size_t samples_to_check = std::min(text_size, SAMPLE_SIZE * 2);

    const uint8_t* disk_text = disk_data.data() + text_offset;
    const uint8_t* mem_text = reinterpret_cast<const uint8_t*>(mem_base + text_offset);

    int diff_count = 0;
    int total_checked = 0;

    // Check beginning
    for (size_t i = 0; i < std::min(SAMPLE_SIZE, text_size); i++) {
        total_checked++;
        if (mem_text[i] != disk_text[i]) {
            diff_count++;
            if (diff_count == 1) {
                LOGD("First diff at offset +0x%zx: mem=0x%02x disk=0x%02x",
                     i, mem_text[i], disk_text[i]);
            }
        }
    }

    // Check end
    if (text_size > SAMPLE_SIZE) {
        size_t end_offset = text_size - SAMPLE_SIZE;
        for (size_t i = 0; i < SAMPLE_SIZE; i++) {
            total_checked++;
            if (mem_text[end_offset + i] != disk_text[end_offset + i]) {
                diff_count++;
            }
        }
    }

    float diff_rate = (float)diff_count / total_checked;
    LOGD("Comparison result: %d/%d bytes differ (%.2f%%)",
         diff_count, total_checked, diff_rate * 100);

    // Threshold: >1% difference indicates potential hook
    return diff_rate > 0.01f;
}

bool IntegrityDetector::checkInlineHook(uintptr_t func_addr) {
    if (func_addr == 0) return false;

    const uint32_t* instructions = reinterpret_cast<const uint32_t*>(func_addr);

    // Check first 4 instructions for common hook patterns

#if defined(__aarch64__)
    // ARM64 hook patterns
    for (int i = 0; i < 4; i++) {
        uint32_t instr = instructions[i];

        // Check for B (unconditional branch): 000101xx xxxxxxxx xxxxxxxx xxxxxxxx
        if ((instr & 0xFC000000) == 0x14000000) {
            LOGW("Inline hook detected at 0x%lx: B instruction at +%d", func_addr, i * 4);
            return true;
        }

        // Check for BL (branch with link): 100101xx xxxxxxxx xxxxxxxx xxxxxxxx
        if ((instr & 0xFC000000) == 0x94000000) {
            LOGW("Inline hook detected at 0x%lx: BL instruction at +%d", func_addr, i * 4);
            return true;
        }

        // Check for BR (branch to register): 11010110 00011111 000000xx xxx00000
        if ((instr & 0xFFFFFC1F) == 0xD61F0000) {
            LOGW("Inline hook detected at 0x%lx: BR instruction at +%d", func_addr, i * 4);
            return true;
        }

        // Check for LDR + BR combo (common trampoline)
        if ((instr & 0xFF000000) == 0x58000000) { // LDR (literal)
            uint32_t next_instr = instructions[i + 1];
            if ((next_instr & 0xFFFFFC1F) == 0xD61F0000) { // BR
                LOGW("Inline hook detected at 0x%lx: LDR+BR combo at +%d", func_addr, i * 4);
                return true;
            }
        }
    }
#elif defined(__arm__)
    // ARM32 hook patterns
    for (int i = 0; i < 4; i++) {
        uint32_t instr = instructions[i];

        // Check for B: 1010xxxx xxxxxxxx xxxxxxxx xxxxxxxx
        if ((instr & 0x0F000000) == 0x0A000000) {
            LOGW("Inline hook detected at 0x%lx: B instruction at +%d", func_addr, i * 4);
            return true;
        }

        // Check for BL: 1011xxxx xxxxxxxx xxxxxxxx xxxxxxxx
        if ((instr & 0x0F000000) == 0x0B000000) {
            LOGW("Inline hook detected at 0x%lx: BL instruction at +%d", func_addr, i * 4);
            return true;
        }

        // Check for BX: xxxx0001 0010xxxx xxxx0001 xxxx0000
        if ((instr & 0x0FFFFFF0) == 0x012FFF10) {
            LOGW("Inline hook detected at 0x%lx: BX instruction at +%d", func_addr, i * 4);
            return true;
        }
    }
#endif

    return false;
}

bool IntegrityDetector::checkLibraryIntegrity(const char* lib_name) {
    LOGD("=== Checking integrity of %s ===", lib_name);

    // Find library in memory
    uintptr_t base_addr = findLibraryBase(lib_name);
    if (base_addr == 0) {
        LOGW("Library %s not loaded in memory", lib_name);
        return true; // Not loaded, can't check
    }

    // Get library file path
    std::string lib_path = getLibraryPath(lib_name);
    if (lib_path.empty()) {
        LOGW("Failed to get path for %s", lib_name);
        return true; // Can't verify
    }

    // Read library file from disk
    std::vector<uint8_t> disk_data = readLibraryFile(lib_path);
    if (disk_data.empty()) {
        LOGW("Failed to read library file: %s", lib_path.c_str());
        return true; // Can't verify
    }

    // Parse ELF and find .text section
    size_t text_offset, text_size;
    if (!parseElfAndFindTextSection(disk_data, text_offset, text_size)) {
        LOGW("Failed to parse ELF or find .text section");
        return true; // Can't verify
    }

    // Compare memory and disk .text sections
    bool is_hooked = compareTextSections(base_addr, disk_data, text_offset, text_size);

    if (is_hooked) {
        LOGW("!!! INTEGRITY VIOLATION DETECTED in %s !!!", lib_name);
    } else {
        LOGD("%s integrity check PASSED", lib_name);
    }

    return !is_hooked; // Return true if clean (not hooked)
}

bool IntegrityDetector::checkFunctionHook(const char* lib_name, const char* func_name) {
    // Use dlopen/dlsym to find function address
    void* handle = dlopen(lib_name, RTLD_NOW);
    if (!handle) {
        LOGW("Failed to dlopen %s: %s", lib_name, dlerror());
        return false;
    }

    void* func_addr = dlsym(handle, func_name);
    dlclose(handle);

    if (!func_addr) {
        LOGW("Failed to find function %s in %s", func_name, lib_name);
        return false;
    }

    LOGD("Checking function %s at 0x%lx", func_name, (uintptr_t)func_addr);
    return checkInlineHook((uintptr_t)func_addr);
}

bool IntegrityDetector::checkLibcIntegrity() {
    LOGD("=== Checking libc.so integrity ===");

    // Method 1: Check library file integrity
    bool lib_integrity = checkLibraryIntegrity("libc.so");

    // Method 2: Check critical functions for inline hooks
    int hooked_functions = 0;
    for (int i = 0; CRITICAL_LIBC_FUNCTIONS[i] != nullptr; i++) {
        if (checkFunctionHook("libc.so", CRITICAL_LIBC_FUNCTIONS[i])) {
            LOGW("Function %s appears to be hooked!", CRITICAL_LIBC_FUNCTIONS[i]);
            hooked_functions++;
        }
    }

    bool result = lib_integrity && (hooked_functions == 0);
    LOGD("libc.so integrity check: %s (hooked_functions: %d)",
         result ? "PASS" : "FAIL", hooked_functions);

    return result;
}

bool IntegrityDetector::checkLibartIntegrity() {
    LOGD("=== Checking libart.so integrity ===");
    return checkLibraryIntegrity("libart.so");
}

bool IntegrityDetector::checkAndroidRuntimeIntegrity() {
    LOGD("=== Checking libandroid_runtime.so integrity ===");
    return checkLibraryIntegrity("libandroid_runtime.so");
}

IntegrityDetector::IntegrityResult IntegrityDetector::checkAllSystemLibraries() {
    LOGD("=== Starting comprehensive system library integrity check ===");

    IntegrityResult result;
    result.is_clean = true;
    result.total_libs_checked = 0;
    result.hooked_libs_count = 0;

    // List of critical libraries to check
    const char* critical_libs[] = {
        "libc.so",
        "libart.so",
        "libandroid_runtime.so",
        "libutils.so",
        "libbinder.so",
        nullptr
    };

    for (int i = 0; critical_libs[i] != nullptr; i++) {
        result.total_libs_checked++;

        LibraryInfo lib_info;
        lib_info.name = critical_libs[i];
        lib_info.path = getLibraryPath(critical_libs[i]);
        lib_info.base_addr = findLibraryBase(critical_libs[i]);
        lib_info.is_hooked = !checkLibraryIntegrity(critical_libs[i]);

        if (lib_info.is_hooked) {
            result.hooked_libs_count++;
            result.is_clean = false;
            lib_info.hook_details = "Memory/disk mismatch detected";
            LOGW("Library %s: HOOKED", critical_libs[i]);
        } else {
            lib_info.hook_details = "Clean";
            LOGD("Library %s: CLEAN", critical_libs[i]);
        }

        result.libraries.push_back(lib_info);
    }

    // Generate summary
    std::ostringstream oss;
    oss << "Checked " << result.total_libs_checked << " libraries, "
        << result.hooked_libs_count << " hooked, "
        << (result.total_libs_checked - result.hooked_libs_count) << " clean";
    result.summary = oss.str();

    LOGD("=== Integrity check complete: %s ===", result.summary.c_str());

    return result;
}

std::string IntegrityDetector::getIntegrityReport() {
    IntegrityResult result = checkAllSystemLibraries();

    std::ostringstream json;
    json << "{\n";
    json << "  \"is_clean\": " << (result.is_clean ? "true" : "false") << ",\n";
    json << "  \"total_checked\": " << result.total_libs_checked << ",\n";
    json << "  \"hooked_count\": " << result.hooked_libs_count << ",\n";
    json << "  \"summary\": \"" << result.summary << "\",\n";
    json << "  \"libraries\": [\n";

    for (size_t i = 0; i < result.libraries.size(); i++) {
        const LibraryInfo& lib = result.libraries[i];
        json << "    {\n";
        json << "      \"name\": \"" << lib.name << "\",\n";
        json << "      \"path\": \"" << lib.path << "\",\n";
        json << "      \"base_addr\": \"0x" << std::hex << lib.base_addr << std::dec << "\",\n";
        json << "      \"is_hooked\": " << (lib.is_hooked ? "true" : "false") << ",\n";
        json << "      \"details\": \"" << lib.hook_details << "\"\n";
        json << "    }" << (i < result.libraries.size() - 1 ? "," : "") << "\n";
    }

    json << "  ]\n";
    json << "}\n";

    return json.str();
}

bool IntegrityDetector::checkPltGotHooks(const std::string& lib_name) {
    // TODO: Implement PLT/GOT hook detection
    // This would parse the ELF PLT/GOT tables and verify they point to expected addresses
    return false;
}
