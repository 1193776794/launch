#ifndef LAUNCH_INTEGRITY_DETECTOR_H
#define LAUNCH_INTEGRITY_DETECTOR_H

#include <string>
#include <vector>
#include <map>

/**
 * Memory integrity detector for system libraries
 * Detects hooks in critical SO files like libc.so, libart.so
 */
class IntegrityDetector {
public:
    struct LibraryInfo {
        std::string name;
        std::string path;
        uintptr_t base_addr;
        size_t size;
        bool is_hooked;
        std::string hook_details;
    };

    struct IntegrityResult {
        bool is_clean;
        int total_libs_checked;
        int hooked_libs_count;
        std::vector<LibraryInfo> libraries;
        std::string summary;
    };

    /**
     * Check libc.so integrity
     * Detects hooks in critical functions: open, read, access, stat, etc.
     */
    static bool checkLibcIntegrity();

    /**
     * Check libart.so integrity
     * Detects hooks in ART runtime functions
     */
    static bool checkLibartIntegrity();

    /**
     * Check libandroid_runtime.so integrity
     */
    static bool checkAndroidRuntimeIntegrity();

    /**
     * Check all critical system libraries
     * Returns detailed report
     */
    static IntegrityResult checkAllSystemLibraries();

    /**
     * Check specific library integrity
     * @param lib_name Library name (e.g., "libc.so")
     * @return true if integrity check passed (no hooks detected)
     */
    static bool checkLibraryIntegrity(const char* lib_name);

    /**
     * Check if a specific function has inline hooks
     * @param lib_name Library name
     * @param func_name Function name
     * @return true if hook detected
     */
    static bool checkFunctionHook(const char* lib_name, const char* func_name);

    /**
     * Get detailed integrity report as JSON string
     */
    static std::string getIntegrityReport();

private:
    /**
     * Find library base address from /proc/self/maps
     */
    static uintptr_t findLibraryBase(const std::string& lib_name);

    /**
     * Get library file path from /proc/self/maps
     */
    static std::string getLibraryPath(const std::string& lib_name);

    /**
     * Read library file from disk using direct syscalls
     */
    static std::vector<uint8_t> readLibraryFile(const std::string& path);

    /**
     * Parse ELF header and find .text section
     * @param text_offset  [out] file offset of .text
     * @param text_size    [out] size of .text
     * @param text_vaddr   [out] virtual address of .text (for memory mapping)
     */
    static bool parseElfAndFindTextSection(const std::vector<uint8_t>& elf_data,
                                          size_t& text_offset,
                                          size_t& text_size,
                                          size_t& text_vaddr);

    /**
     * Compare memory and disk .text section
     * @param mem_base  Load base address of the library in memory
     * @param disk_data ELF file bytes from disk
     * @param text_offset File offset of .text
     * @param text_size   Size of .text
     * @param text_vaddr  Virtual address of .text (used to compute memory address)
     * @return true if different (hooked)
     */
    static bool compareTextSections(uintptr_t mem_base,
                                   const std::vector<uint8_t>& disk_data,
                                   size_t text_offset,
                                   size_t text_size,
                                   size_t text_vaddr);

    /**
     * Check for inline hooks in function prologue
     * Detects common hook patterns:
     * - ARM64: B/BL/BR instructions at function entry
     * - ARM32: B/BL/BX instructions
     */
    static bool checkInlineHook(uintptr_t func_addr);

    /**
     * Check PLT/GOT hooks
     */
    static bool checkPltGotHooks(const std::string& lib_name);

    /**
     * Calculate CRC32 of memory region
     */
    static uint32_t calculateCRC32(const uint8_t* data, size_t size);

    /**
     * List of critical functions to check in libc
     */
    static const char* CRITICAL_LIBC_FUNCTIONS[];

    /**
     * List of critical functions to check in libart
     */
    static const char* CRITICAL_LIBART_FUNCTIONS[];

    /**
     * List of critical dlopen-related functions to check
     * These are in libdl.so or the dynamic linker
     */
    static const char* CRITICAL_DLOPEN_FUNCTIONS[];

    /**
     * Check linker functions by directly parsing ELF from disk
     * Bypasses dlopen/dlsym (which may themselves be hooked)
     * @return number of hooked linker functions found
     */
    static int checkLinkerFunctions();
};

#endif // LAUNCH_INTEGRITY_DETECTOR_H
