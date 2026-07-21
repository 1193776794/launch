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
    "__system_property_get", "getprop",
    "dlopen", "dlsym", "dlclose",               // libdl functions (often in libc on newer Android)
    "connect", "sendto", "recvfrom",             // network functions
    "mmap", "mprotect", "munmap",                // memory management
    "ptrace",                                     // anti-debug
    "kill", "execve", "fork",                    // process control
    nullptr
};

const char* IntegrityDetector::CRITICAL_LIBART_FUNCTIONS[] = {
    "_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc", // ArtMethod::Invoke
    "_ZN3art11ClassLinker17RegisterDexFileERKNS_7DexFileE",     // ClassLinker::RegisterDexFile
    nullptr
};

// dlopen-related functions: these are the primary targets for SO injection hooking.
// On Android:
//   - dlopen/dlsym/dlclose: in libdl.so (or merged into libc.so on Android 12+)
//   - android_dlopen_ext: in libdl.so
//   - __loader_android_dlopen_ext / __loader_dlopen: in the dynamic linker (linker64/linker)
const char* IntegrityDetector::CRITICAL_DLOPEN_FUNCTIONS[] = {
    "dlopen", "dlsym", "dlclose", "android_dlopen_ext",
    "__loader_dlopen", "__loader_android_dlopen_ext",
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

    // Find the FIRST mapping of this library — this is the load base address.
    // On Android, the first mapping is typically r--p (ELF headers + read-only data),
    // followed by r-xp (.text), then rw-p (.data/.bss).
    // The load base is the start address of the first mapping.
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find(lib_name) != std::string::npos && line.find(".so") != std::string::npos) {
            uintptr_t start;
            if (sscanf(line.c_str(), "%lx", &start) == 1) {
                LOGD("Found %s load base: 0x%lx (from: %s)", lib_name.c_str(), start, line.c_str());
                return start;
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

    // Limit to reasonable size (64MB — libart.so 已达 ~13MB,旧 10MB 上限会截断到 .text 之前)
    if (file_size > 64 * 1024 * 1024) {
        LOGW("Library file too large: %zu bytes, limiting to 64MB", file_size);
        file_size = 64 * 1024 * 1024;
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
                                                   size_t& text_size,
                                                   size_t& text_vaddr) {
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
                    text_vaddr = shdr->sh_addr;
                    LOGD("Found .text section: offset=0x%zx, size=0x%zx, vaddr=0x%zx",
                         text_offset, text_size, text_vaddr);
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
                    text_vaddr = shdr->sh_addr;
                    LOGD("Found .text section (32-bit): offset=0x%zx, size=0x%zx, vaddr=0x%zx",
                         text_offset, text_size, text_vaddr);
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
                                           size_t text_size,
                                           size_t text_vaddr) {
    if (text_offset + text_size > disk_data.size()) {
        LOGE("Invalid .text section bounds: offset=0x%zx size=0x%zx file=0x%zx",
             text_offset, text_size, disk_data.size());
        return false;
    }

    // Memory address of .text = library load base + section virtual address (sh_addr).
    // mem_base is the address of the library's first mapping in /proc/self/maps.
    // For position-independent shared libraries on Android, the first PT_LOAD segment
    // usually has p_vaddr=0, so mem_base + sh_addr gives the correct address.
    // If p_vaddr != 0, we need to subtract it, but this is rare for Android .so files.
    uintptr_t mem_text_addr = mem_base + text_vaddr;

    LOGD("compareTextSections: mem_base=0x%lx + text_vaddr=0x%zx = mem_text=0x%lx, text_size=0x%zx",
         mem_base, text_vaddr, mem_text_addr, text_size);

    // [XFF] Hunter 风格:**直接指针**读 .text 逐字节比对(不走 /proc/self/mem)。
    // 关键:沙箱屏蔽了 /proc/self/mem 打开(旧版在此静默 skip→假 PASSED),且内核 READ_ORIG(K3-V2)
    // 只拦 /proc/pid/mem·ptrace·process_vm_readv 这些 remote 读,**进程内裸指针读拦不到** → 直读能看到
    // 真实(被 hook 后)字节,正是 Hunter 的 detect_elf_checksum 干的事。r-x 页在 SM8550(无 EPAN)可读。
    const uint8_t* disk_text = disk_data.data() + text_offset;
    const volatile uint8_t* mem_text = reinterpret_cast<const volatile uint8_t*>(mem_text_addr);
    size_t diff_count = 0;
    long first_diff = -1;
    uint8_t first_mem = 0, first_disk = 0;
    for (size_t i = 0; i < text_size; i++) {
        uint8_t mv = mem_text[i];
        if (mv != disk_text[i]) {
            if (first_diff < 0) { first_diff = (long)i; first_mem = mv; first_disk = disk_text[i]; }
            diff_count++;
        }
    }

    if (first_diff >= 0) {
        LOGW("[XFF-CRC] .text DIRTY: %zu bytes differ, first@.text+0x%lx (mem=0x%02x disk=0x%02x) mem_text=0x%lx size=0x%zx",
             diff_count, first_diff, first_mem, first_disk, mem_text_addr, text_size);
        return true;   // hooked（任一字节不同）
    }
    LOGD("[XFF-CRC] .text CLEAN (%zu bytes all match, mem_text=0x%lx size=0x%zx)",
         text_size, mem_text_addr, text_size);
    return false;
}

/**
 * Cached known library address ranges to avoid re-reading /proc/self/maps per call.
 */
struct MappedRegion {
    uintptr_t start;
    uintptr_t end;
};

static std::vector<MappedRegion> s_known_regions;
static bool s_regions_loaded = false;

static void loadKnownRegions() {
    if (s_regions_loaded) return;
    s_regions_loaded = true;
    s_known_regions.clear();

    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return;

    std::string line;
    while (std::getline(maps, line)) {
        if (line.empty()) continue;
        // Only include file-backed mappings (path starts with '/')
        size_t lastSpace = line.rfind(' ');
        if (lastSpace == std::string::npos) continue;
        std::string path = line.substr(lastSpace + 1);
        if (path.empty() || path[0] != '/') continue;

        uintptr_t start, end;
        if (sscanf(line.c_str(), "%lx-%lx", &start, &end) == 2) {
            s_known_regions.push_back({start, end});
        }
    }
    LOGD("Loaded %zu known library regions from /proc/self/maps", s_known_regions.size());
}

/**
 * Check if an address falls within any known SO mapping (non-anonymous).
 * Uses cached maps data for performance.
 */
static bool isAddressInKnownLibrary(uintptr_t addr) {
    if (addr == 0) return false;
    loadKnownRegions();
    for (const auto& r : s_known_regions) {
        if (addr >= r.start && addr < r.end) return true;
    }
    return false;
}

bool IntegrityDetector::checkInlineHook(uintptr_t func_addr) {
    if (func_addr == 0) return false;

    const uint32_t* instructions = reinterpret_cast<const uint32_t*>(func_addr);

    // Detect hook trampoline patterns, then VERIFY the jump target.
    // Android libdl.so uses LDR X16+BR X16 stubs to forward to the linker — these are normal.
    // Frida/Dobby/ShadowHook use the same pattern but jump to anonymous mmap memory.
    // Key distinction: if target is in a known SO → system stub; if in anon memory → hook.

#if defined(__aarch64__)
    uint32_t instr0 = instructions[0];
    uint32_t instr1 = instructions[1];

    // Pattern 1: LDR Xn, #offset; BR Xn
    if ((instr0 & 0xFF000000) == 0x58000000) { // LDR Xn, #literal
        int rd = instr0 & 0x1F;
        if ((instr1 & 0xFFFFFC1F) == 0xD61F0000) { // BR Xn
            int rn = (instr1 >> 5) & 0x1F;
            if (rd == rn) {
                // Decode the jump target address from the LDR literal
                // LDR Xn, #imm19 — offset = SignExtend(imm19 << 2, 64)
                int32_t imm19 = (int32_t)(instr0 << 8) >> 13;  // sign-extend bits [23:5]
                int64_t offset = (int64_t)imm19 << 2;
                uintptr_t literal_addr = func_addr + offset;

                // Read the target pointer from the literal pool
                uintptr_t target = 0;
                // Safe read via /proc/self/mem
                int fd = open("/proc/self/mem", O_RDONLY);
                if (fd >= 0) {
                    if (pread(fd, &target, sizeof(target), (off_t)literal_addr) == sizeof(target)) {
                        // Check if target is in a known library
                        if (isAddressInKnownLibrary(target)) {
                            LOGD("LDR+BR at 0x%lx jumps to 0x%lx (known library) — system stub, not hook",
                                 func_addr, target);
                            close(fd);
                            return false;  // Normal system PLT stub
                        } else {
                            LOGW("Inline hook at 0x%lx: LDR X%d+BR X%d → target 0x%lx (anonymous memory!)",
                                 func_addr, rd, rn, target);
                            close(fd);
                            return true;  // Jump to anonymous memory = hook
                        }
                    }
                    close(fd);
                }

                // If we can't read the target, report as suspicious
                LOGW("Inline hook at 0x%lx: LDR X%d+BR X%d (unable to verify target)", func_addr, rd, rn);
                return true;
            }
        }
    }

    // Pattern 2: MOV X16/X17, #imm16; MOVK X16/X17, #imm16, LSL#16; ... BR X16/X17
    if ((instr0 & 0xFFE0001F) == 0xD2800010 || // MOV X16, #imm
        (instr0 & 0xFFE0001F) == 0xD2800011) { // MOV X17, #imm
        int target_reg = instr0 & 0x1F;
        if ((instr1 & 0xFFE0001F) == (0xF2A00000 | target_reg)) { // MOVK Xn, #imm, LSL#16
            // Decode the full immediate to get target address
            uint64_t imm16_0 = (instr0 >> 5) & 0xFFFF;
            uint64_t imm16_1 = (instr1 >> 5) & 0xFFFF;
            uintptr_t target = imm16_0 | (imm16_1 << 16);

            // Check for more MOVK instructions to build full 64-bit address
            for (int i = 2; i < 4; i++) {
                uint32_t next = instructions[i];
                if ((next & 0xFFE0001F) == (0xF2C00000 | target_reg)) { // MOVK LSL#32
                    target |= ((uint64_t)((next >> 5) & 0xFFFF)) << 32;
                } else if ((next & 0xFFE0001F) == (0xF2E00000 | target_reg)) { // MOVK LSL#48
                    target |= ((uint64_t)((next >> 5) & 0xFFFF)) << 48;
                }
            }

            if (target != 0 && !isAddressInKnownLibrary(target)) {
                LOGW("Inline hook at 0x%lx: MOV+MOVK+BR X%d → target 0x%lx (anonymous memory!)",
                     func_addr, target_reg, target);
                return true;
            }
            // Target in known library = normal, not a hook
            LOGD("MOV+MOVK+BR at 0x%lx → 0x%lx (known library), not hook", func_addr, target);
            return false;
        }
    }

#elif defined(__arm__)
    uint32_t instr0 = instructions[0];
    uint32_t instr1 = instructions[1];

    // LDR PC, [PC, #n]: direct PC load
    if ((instr0 & 0x0F7FF000) == 0x051FF000) {
        // Decode offset and read target
        int32_t offset = instr0 & 0xFFF;
        if (!(instr0 & (1 << 23))) offset = -offset;  // U bit
        uintptr_t target_ptr = func_addr + 8 + offset;  // PC+8 in ARM mode
        uintptr_t target = 0;
        int fd = open("/proc/self/mem", O_RDONLY);
        if (fd >= 0) {
            if (pread(fd, &target, 4, (off_t)target_ptr) == 4) {
                close(fd);
                if (isAddressInKnownLibrary(target)) return false;  // Normal
                LOGW("Inline hook at 0x%lx: LDR PC → 0x%lx (anonymous)", func_addr, target);
                return true;
            }
            close(fd);
        }
        return true;  // Can't verify, report suspicious
    }

    // LDR Rn, [PC, #off]; BX Rn
    if ((instr0 & 0x0F7F0000) == 0x051F0000) {
        int rd = (instr0 >> 12) & 0xF;
        if ((instr1 & 0x0FFFFFF0) == 0x012FFF10) {
            int rm = instr1 & 0xF;
            if (rd == rm && rd != 14) {
                int32_t offset = instr0 & 0xFFF;
                if (!(instr0 & (1 << 23))) offset = -offset;
                uintptr_t target_ptr = func_addr + 8 + offset;
                uintptr_t target = 0;
                int fd = open("/proc/self/mem", O_RDONLY);
                if (fd >= 0) {
                    if (pread(fd, &target, 4, (off_t)target_ptr) == 4) {
                        close(fd);
                        if (isAddressInKnownLibrary(target)) return false;
                        LOGW("Inline hook at 0x%lx: LDR+BX → 0x%lx (anonymous)", func_addr, target);
                        return true;
                    }
                    close(fd);
                }
                return true;
            }
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
    size_t text_offset, text_size, text_vaddr;
    if (!parseElfAndFindTextSection(disk_data, text_offset, text_size, text_vaddr)) {
        LOGW("Failed to parse ELF or find .text section");
        return true; // Can't verify
    }

    // Compare memory and disk .text sections
    bool is_hooked = compareTextSections(base_addr, disk_data, text_offset, text_size, text_vaddr);

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

    // Reset cached maps for this detection round
    s_regions_loaded = false;

    // Method 1: Check library file integrity (.text section disk vs memory)
    bool lib_integrity = checkLibraryIntegrity("libc.so");

    // Method 2: Check critical functions for inline hooks via dlsym
    int hooked_functions = 0;
    for (int i = 0; CRITICAL_LIBC_FUNCTIONS[i] != nullptr; i++) {
        if (checkFunctionHook("libc.so", CRITICAL_LIBC_FUNCTIONS[i])) {
            LOGW("Function %s appears to be hooked!", CRITICAL_LIBC_FUNCTIONS[i]);
            hooked_functions++;
        }
    }

    // Method 3: Check dlopen-related functions across multiple libraries
    // These functions may live in libc.so, libdl.so, or the linker depending on Android version.
    // Try each library that might contain them.
    const char* dlopen_libs[] = {"libdl.so", "libc.so", nullptr};
    for (int li = 0; dlopen_libs[li] != nullptr; li++) {
        for (int fi = 0; CRITICAL_DLOPEN_FUNCTIONS[fi] != nullptr; fi++) {
            // Skip __loader_* functions - they're in the linker, not accessible via dlsym
            if (strncmp(CRITICAL_DLOPEN_FUNCTIONS[fi], "__loader_", 9) == 0) continue;

            if (checkFunctionHook(dlopen_libs[li], CRITICAL_DLOPEN_FUNCTIONS[fi])) {
                LOGW("dlopen function %s in %s appears to be hooked!",
                     CRITICAL_DLOPEN_FUNCTIONS[fi], dlopen_libs[li]);
                hooked_functions++;
            }
        }
    }

    // Method 4: Check __loader_* functions directly from /proc/self/maps + ELF parsing
    // These are in the dynamic linker (linker64) and can't be found via dlsym.
    hooked_functions += checkLinkerFunctions();

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

/**
 * Check linker functions (__loader_dlopen, __loader_android_dlopen_ext)
 * by finding their addresses directly from /proc/self/maps + ELF symbol table,
 * bypassing dlopen/dlsym (which may themselves be hooked).
 *
 * @return number of hooked linker functions found
 */
int IntegrityDetector::checkLinkerFunctions() {
    LOGD("=== Checking linker functions ===");
    int hooked_count = 0;

    // Find the linker in /proc/self/maps
    std::string linker_path;
    uintptr_t linker_base = 0;

    std::ifstream maps("/proc/self/maps");
    if (!maps.is_open()) return 0;

    std::string line;
    while (std::getline(maps, line)) {
        // Look for linker64 or linker
        if ((line.find("/linker64") != std::string::npos ||
             line.find("/linker") != std::string::npos) &&
            line.find(".so") == std::string::npos) {  // Exclude liblinker_*.so
            uintptr_t start;
            if (sscanf(line.c_str(), "%lx", &start) == 1) {
                if (linker_base == 0) {
                    linker_base = start;
                }
                // Extract path
                size_t path_start = line.rfind(' ');
                if (path_start != std::string::npos) {
                    std::string path = line.substr(path_start + 1);
                    if (path[0] == '/' && linker_path.empty()) {
                        linker_path = path;
                        LOGD("Found linker: %s at base 0x%lx", linker_path.c_str(), linker_base);
                    }
                }
            }
        }
    }
    maps.close();

    if (linker_path.empty() || linker_base == 0) {
        LOGW("Linker not found in /proc/self/maps");
        return 0;
    }

    // Read linker ELF from disk
    std::vector<uint8_t> linker_data = readLibraryFile(linker_path);
    if (linker_data.empty() || linker_data.size() < sizeof(Elf64_Ehdr)) {
        LOGW("Failed to read linker file");
        return 0;
    }

    // Parse ELF to find .dynsym and .dynstr for symbol resolution
    bool is_64bit = (linker_data[4] == 2);
    if (!is_64bit) {
        LOGD("32-bit linker, skipping for now");
        return 0;
    }

    const Elf64_Ehdr* ehdr = reinterpret_cast<const Elf64_Ehdr*>(linker_data.data());

    // Find .dynsym and .dynstr sections
    const Elf64_Shdr* dynsym_shdr = nullptr;
    const Elf64_Shdr* dynstr_shdr = nullptr;

    // First find section header string table
    if (ehdr->e_shstrndx >= ehdr->e_shnum) return 0;
    size_t shstrtab_off = ehdr->e_shoff + ehdr->e_shstrndx * ehdr->e_shentsize;
    if (shstrtab_off + sizeof(Elf64_Shdr) > linker_data.size()) return 0;
    const Elf64_Shdr* shstrtab = reinterpret_cast<const Elf64_Shdr*>(
        linker_data.data() + shstrtab_off);

    for (int i = 0; i < ehdr->e_shnum; i++) {
        size_t sh_off = ehdr->e_shoff + i * ehdr->e_shentsize;
        if (sh_off + sizeof(Elf64_Shdr) > linker_data.size()) break;
        const Elf64_Shdr* shdr = reinterpret_cast<const Elf64_Shdr*>(
            linker_data.data() + sh_off);

        if (shdr->sh_name >= shstrtab->sh_size) continue;
        const char* name = reinterpret_cast<const char*>(
            linker_data.data() + shstrtab->sh_offset + shdr->sh_name);

        if (strcmp(name, ".dynsym") == 0) dynsym_shdr = shdr;
        if (strcmp(name, ".dynstr") == 0) dynstr_shdr = shdr;
    }

    if (!dynsym_shdr || !dynstr_shdr) {
        LOGW("Could not find .dynsym/.dynstr in linker");
        return 0;
    }

    // Search for __loader_* symbols
    const char* target_funcs[] = {
        "__loader_dlopen",
        "__loader_android_dlopen_ext",
        "android_dlopen_ext",
        nullptr
    };

    size_t sym_count = dynsym_shdr->sh_size / sizeof(Elf64_Sym);
    const Elf64_Sym* syms = reinterpret_cast<const Elf64_Sym*>(
        linker_data.data() + dynsym_shdr->sh_offset);

    for (size_t s = 0; s < sym_count; s++) {
        if (syms[s].st_name == 0 || syms[s].st_value == 0) continue;
        if (syms[s].st_name >= dynstr_shdr->sh_size) continue;

        const char* sym_name = reinterpret_cast<const char*>(
            linker_data.data() + dynstr_shdr->sh_offset + syms[s].st_name);

        for (int t = 0; target_funcs[t] != nullptr; t++) {
            if (strcmp(sym_name, target_funcs[t]) == 0) {
                uintptr_t func_addr = linker_base + syms[s].st_value;
                LOGD("Found %s at 0x%lx (linker_base=0x%lx + sym_value=0x%lx)",
                     sym_name, func_addr, linker_base, (unsigned long)syms[s].st_value);

                if (checkInlineHook(func_addr)) {
                    LOGW("!!! Linker function %s at 0x%lx is HOOKED !!!", sym_name, func_addr);
                    hooked_count++;
                }
                break;
            }
        }
    }

    LOGD("Linker function check complete: %d hooked", hooked_count);
    return hooked_count;
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
        "libdl.so",
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

// [XFF] Hunter 风格补充:linker64 全 r-x 直读比对 + rwx 段扫描(Hunter:mem!=disk 或 rwx 段=hooked)。
static void xff_raw_scan() {
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        uintptr_t s=0,e=0; char perms[8]={0}; unsigned long off=0; char path[600]={0};
        int n = sscanf(line.c_str(), "%lx-%lx %7s %lx %*s %*s %599[^\n]", &s,&e,perms,&off,path);
        if (n < 4) continue;
        if (perms[0]=='r'&&perms[1]=='w'&&perms[2]=='x')
            LOGW("[XFF-RAW] RWX segment %lx-%lx off=0x%lx %s", s,e,off, path[0]?path:"[anon]");
        if (perms[0]=='r'&&perms[2]=='x'&&path[0]=='/' &&
            (strstr(path,"linker64")||strstr(path,"libandroid_servers_ext")||strstr(path,"liblspd"))) {
            size_t len=e-s;
            int fd=open(path,O_RDONLY); if(fd<0) continue;
            std::vector<uint8_t> disk(len); ssize_t g=pread(fd,disk.data(),(size_t)len,(off_t)off); close(fd);
            if(g<=0) continue;
            const volatile uint8_t* mem=(const volatile uint8_t*)s;
            long first=-1; size_t dc=0; uint8_t fm=0,fd8=0;
            for(size_t i=0;i<(size_t)g;i++){ uint8_t mv=mem[i]; if(mv!=disk[i]){ if(first<0){first=(long)i;fm=mv;fd8=disk[i];} dc++; } }
            if(first>=0) LOGW("[XFF-RAW] %s r-x DIRTY %zu bytes first@0x%lx (mem=0x%02x disk=0x%02x) map=0x%lx off=0x%lx", path, dc, first, fm, fd8, s, off);
            else LOGD("[XFF-RAW] %s r-x CLEAN (%zd bytes)", path, g);
        }
    }
}

std::string IntegrityDetector::getIntegrityReport() {
    xff_raw_scan();
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
