#ifndef LAUNCH_SYSCALL_WRAPPER_H
#define LAUNCH_SYSCALL_WRAPPER_H

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <string>

// Architecture-specific syscall number compatibility
// These are fallback definitions in case <sys/syscall.h> doesn't provide them

// Common syscall numbers (similar across architectures)
#ifndef __NR_read
    #if defined(__aarch64__) || defined(__x86_64__)
        #define __NR_read 63
    #elif defined(__i386__)
        #define __NR_read 3
    #elif defined(__arm__)
        #define __NR_read 3
    #endif
#endif

#ifndef __NR_close
    #if defined(__aarch64__) || defined(__x86_64__)
        #define __NR_close 57
    #elif defined(__i386__)
        #define __NR_close 6
    #elif defined(__arm__)
        #define __NR_close 6
    #endif
#endif

#if defined(__i386__)
    // x86 32-bit specific syscall numbers
    #ifndef __NR_faccessat
        #define __NR_faccessat 307
    #endif
    #ifndef __NR_openat
        #define __NR_openat 295
    #endif
    #ifndef __NR_fstatat64
        #define __NR_fstatat64 300
    #endif
    #ifndef __NR_getdents64
        #define __NR_getdents64 220
    #endif
#elif defined(__x86_64__)
    // x86_64 specific syscall numbers
    #ifndef __NR_faccessat
        #define __NR_faccessat 269
    #endif
    #ifndef __NR_openat
        #define __NR_openat 257
    #endif
    #ifndef __NR_newfstatat
        #define __NR_newfstatat 262
    #endif
    #ifndef __NR_getdents64
        #define __NR_getdents64 217
    #endif
#elif defined(__arm__)
    // ARM 32-bit specific syscall numbers
    #ifndef __NR_faccessat
        #define __NR_faccessat 334
    #endif
    #ifndef __NR_openat
        #define __NR_openat 322
    #endif
    #ifndef __NR_fstatat64
        #define __NR_fstatat64 327
    #endif
    #ifndef __NR_getdents64
        #define __NR_getdents64 217
    #endif
#elif defined(__aarch64__)
    // ARM64 specific syscall numbers
    #ifndef __NR_faccessat
        #define __NR_faccessat 48
    #endif
    #ifndef __NR_openat
        #define __NR_openat 56
    #endif
    #ifndef __NR_newfstatat
        #define __NR_newfstatat 79
    #endif
    #ifndef __NR_getdents64
        #define __NR_getdents64 61
    #endif
#endif

/**
 * Direct syscall wrappers to bypass libc hooks
 * These functions use SVC instruction directly on ARM/ARM64
 */

#if defined(__aarch64__)
// ARM64 direct syscall implementation
static inline long syscall_raw(long number, long arg0 = 0, long arg1 = 0,
                                long arg2 = 0, long arg3 = 0,
                                long arg4 = 0, long arg5 = 0) {
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = arg0;
    register long x1 __asm__("x1") = arg1;
    register long x2 __asm__("x2") = arg2;
    register long x3 __asm__("x3") = arg3;
    register long x4 __asm__("x4") = arg4;
    register long x5 __asm__("x5") = arg5;
    __asm__ volatile(
        "svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
        : "memory"
    );
    return x0;
}
#elif defined(__arm__)
// ARM32: Use standard syscall to avoid r7 frame pointer conflict in thumb mode
// Direct inline assembly doesn't work reliably with thumb mode (-mthumb)
static inline long syscall_raw(long number, long arg0 = 0, long arg1 = 0,
                                long arg2 = 0, long arg3 = 0,
                                long arg4 = 0, long arg5 = 0) {
    return syscall(number, arg0, arg1, arg2, arg3, arg4, arg5);
}
#elif defined(__i386__) || defined(__x86_64__)
// x86/x86_64: Use standard syscall function
// Note: x86 doesn't benefit much from inline assembly due to different calling convention
static inline long syscall_raw(long number, long arg0 = 0, long arg1 = 0,
                                long arg2 = 0, long arg3 = 0,
                                long arg4 = 0, long arg5 = 0) {
    return syscall(number, arg0, arg1, arg2, arg3, arg4, arg5);
}
#else
// Fallback to standard syscall for other architectures
static inline long syscall_raw(long number, long arg0 = 0, long arg1 = 0,
                                long arg2 = 0, long arg3 = 0,
                                long arg4 = 0, long arg5 = 0) {
    return syscall(number, arg0, arg1, arg2, arg3, arg4, arg5);
}
#endif

/**
 * Check if file exists using direct syscall
 * @param path File path to check
 * @return 0 if exists, -1 if not
 */
static inline int syscall_access(const char *path) {
    return (int)syscall_raw(__NR_faccessat, AT_FDCWD, (long)path, F_OK, 0);
}

/**
 * Open file using direct syscall
 * @param path File path
 * @param flags Open flags
 * @return File descriptor or -1 on error
 */
static inline int syscall_open(const char *path, int flags) {
    return (int)syscall_raw(__NR_openat, AT_FDCWD, (long)path, flags, 0);
}

/**
 * Read from file using direct syscall
 * @param fd File descriptor
 * @param buf Buffer to read into
 * @param count Number of bytes to read
 * @return Number of bytes read or -1 on error
 */
static inline ssize_t syscall_read(int fd, void *buf, size_t count) {
    return (ssize_t)syscall_raw(__NR_read, fd, (long)buf, count);
}

/**
 * Close file using direct syscall
 * @param fd File descriptor
 * @return 0 on success, -1 on error
 */
static inline int syscall_close(int fd) {
    return (int)syscall_raw(__NR_close, fd);
}

/**
 * Get file status using direct syscall
 * @param path File path
 * @param buf Stat buffer
 * @return 0 on success, -1 on error
 */
static inline int syscall_stat(const char *path, struct stat *buf) {
#if defined(__aarch64__)
    // ARM64: Use newfstatat
    return (int)syscall_raw(__NR_newfstatat, AT_FDCWD, (long)path, (long)buf, 0);
#elif defined(__arm__)
    // ARM32: Use fstatat64
    return (int)syscall_raw(__NR_fstatat64, AT_FDCWD, (long)path, (long)buf, 0);
#elif defined(__i386__)
    // x86 32-bit: Use fstatat64
    return (int)syscall_raw(__NR_fstatat64, AT_FDCWD, (long)path, (long)buf, 0);
#elif defined(__x86_64__)
    // x86_64: Use newfstatat
    return (int)syscall_raw(__NR_newfstatat, AT_FDCWD, (long)path, (long)buf, 0);
#else
    // Fallback to standard stat
    return stat(path, buf);
#endif
}

/**
 * Read file content using direct syscall
 * @param path File path
 * @param maxSize Maximum size to read
 * @return File content as string
 */
static inline std::string syscall_read_file(const char *path, size_t maxSize = 4096) {
    int fd = syscall_open(path, O_RDONLY);
    if (fd < 0) return "";

    char *buf = new char[maxSize + 1];
    ssize_t bytesRead = syscall_read(fd, buf, maxSize);
    syscall_close(fd);

    std::string result;
    if (bytesRead > 0) {
        buf[bytesRead] = '\0';
        result = std::string(buf, bytesRead);
    }
    delete[] buf;
    return result;
}

/**
 * Check if file exists and is readable using direct syscall
 * @param path File path
 * @return true if exists
 */
static inline bool syscall_file_exists(const char *path) {
    return syscall_access(path) == 0;
}

/**
 * Get directory entries using direct syscall
 * @param path Directory path
 * @param buffer Buffer for entries
 * @param bufferSize Buffer size
 * @return Number of bytes read or -1 on error
 */
static inline int syscall_getdents(const char *path, void *buffer, size_t bufferSize) {
    int fd = syscall_open(path, O_RDONLY | O_DIRECTORY);
    if (fd < 0) return -1;

    int bytesRead = (int)syscall_raw(__NR_getdents64, fd, (long)buffer, bufferSize);
    syscall_close(fd);
    return bytesRead;
}

// ===================== Timing Attack Detection =====================

#include <time.h>

/**
 * Get high-resolution monotonic time in nanoseconds
 * Uses CLOCK_MONOTONIC_RAW to avoid NTP adjustments
 */
static inline long long get_monotonic_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/**
 * Benchmark syscall timing - measure time for N iterations
 * This detects Hook frameworks by timing anomalies
 *
 * @param iterations Number of times to call the syscall
 * @return Average time per call in nanoseconds
 */
static inline long long benchmark_syscall_openat(int iterations) {
    const char* dummy_path = "/dev/null";

    long long start = get_monotonic_time_ns();

    for (int i = 0; i < iterations; i++) {
        // Direct syscall - should be very fast (~100-500ns)
        syscall_raw(__NR_openat, AT_FDCWD, (long)dummy_path, O_RDONLY, 0);
        // Note: We intentionally don't check return value or close fd
        // to minimize measurement overhead
    }

    long long end = get_monotonic_time_ns();
    long long total_time = end - start;

    return total_time / iterations;  // Average time per call
}

/**
 * Benchmark libc openat timing - measure time for N iterations using libc
 * If Hook framework intercepts libc calls, this will be slower
 *
 * @param iterations Number of times to call the function
 * @return Average time per call in nanoseconds
 */
static inline long long benchmark_libc_openat(int iterations) {
    const char* dummy_path = "/dev/null";

    long long start = get_monotonic_time_ns();

    for (int i = 0; i < iterations; i++) {
        // Call through libc - can be hooked by Frida/Xposed
        open(dummy_path, O_RDONLY);
    }

    long long end = get_monotonic_time_ns();
    long long total_time = end - start;

    return total_time / iterations;
}

/**
 * Benchmark syscall access timing
 */
static inline long long benchmark_syscall_access(int iterations) {
    const char* dummy_path = "/system/bin/sh";

    long long start = get_monotonic_time_ns();

    for (int i = 0; i < iterations; i++) {
        syscall_raw(__NR_faccessat, AT_FDCWD, (long)dummy_path, F_OK, 0);
    }

    long long end = get_monotonic_time_ns();
    return (end - start) / iterations;
}

/**
 * Benchmark libc access timing
 */
static inline long long benchmark_libc_access(int iterations) {
    const char* dummy_path = "/system/bin/sh";

    long long start = get_monotonic_time_ns();

    for (int i = 0; i < iterations; i++) {
        access(dummy_path, F_OK);
    }

    long long end = get_monotonic_time_ns();
    return (end - start) / iterations;
}

/**
 * Benchmark syscall stat timing
 */
static inline long long benchmark_syscall_stat(int iterations) {
    const char* dummy_path = "/system/build.prop";
    struct stat st;

    long long start = get_monotonic_time_ns();

    for (int i = 0; i < iterations; i++) {
        // Call through syscall_stat which handles architecture differences
        syscall_stat(dummy_path, &st);
    }

    long long end = get_monotonic_time_ns();
    return (end - start) / iterations;
}

/**
 * Benchmark libc stat timing
 */
static inline long long benchmark_libc_stat(int iterations) {
    const char* dummy_path = "/system/build.prop";
    struct stat st;

    long long start = get_monotonic_time_ns();

    for (int i = 0; i < iterations; i++) {
        stat(dummy_path, &st);
    }

    long long end = get_monotonic_time_ns();
    return (end - start) / iterations;
}

/**
 * Detect timing anomaly - compare syscall vs libc timing
 *
 * @param syscall_time Average syscall time (ns)
 * @param libc_time Average libc time (ns)
 * @param threshold_multiplier If libc_time > syscall_time * multiplier, suspicious
 * @return true if timing anomaly detected (likely hooked)
 */
static inline bool detect_timing_anomaly(long long syscall_time, long long libc_time,
                                         float threshold_multiplier = 3.0f) {
    // Normal case: libc might be slightly slower than syscall (1-2x)
    // Hooked case: libc is MUCH slower (5-100x)

    if (syscall_time <= 0) return false;  // Invalid measurement

    float ratio = (float)libc_time / (float)syscall_time;
    return ratio > threshold_multiplier;
}

// ===================== KernelSU Side-Channel Detection =====================
// Timing side-channel detection for KernelSU kernel-level syscall hooks.
//
// Key insight: KernelSU hooks __NR_faccessat (syscall 48 on ARM64) to intercept
// file access checks. __NR_fchownat is NOT hooked by KernelSU.
// Normally, faccessat is faster than fchownat. If faccessat is hooked by KernelSU,
// it will consistently be slower than fchownat due to the hook overhead.
//
// Detection flow:
// 1. Collect N timing samples for both faccessat and fchownat
// 2. Sort both arrays to reduce noise and extreme outliers
// 3. Compare element-by-element: count how many times faccessat > fchownat + 1
// 4. If anomaly count exceeds threshold (70%), KernelSU hook is likely present

#include <cstdlib>
#include <cstring>
#include <sched.h>

// Number of timing samples to collect
#define KSU_NUM_SAMPLES 10000

// Anomaly threshold: 7000 out of 10000 (70%)
// Threshold 0x1B58 = 7000
#define KSU_ANOMALY_THRESHOLD 7000

/**
 * Read hardware counter for precise timing (ARM64 only)
 * Uses ISB + CNTVCT_EL0 + ISB pattern for nanosecond-level accuracy.
 *
 * On non-ARM64, falls back to CLOCK_MONOTONIC_RAW
 */
static inline uint64_t ksu_read_counter() {
#if defined(__aarch64__)
    uint64_t val;
    // ISB ensures all previous instructions complete before reading counter
    __asm__ volatile("isb" ::: "memory");
    // Read virtual counter register (CNTVCT_EL0) for nanosecond precision
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(val));
    __asm__ volatile("isb" ::: "memory");
    return val;
#else
    // Fallback for non-ARM64 architectures
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

/**
 * Comparator for qsort - ascending order for int64_t timing values
 */
static int ksu_compare_int64(const void* a, const void* b) {
    int64_t va = *(const int64_t*)a;
    int64_t vb = *(const int64_t*)b;
    if (va < vb) return -1;
    if (va > vb) return 1;
    return 0;
}

/**
 * Try to bind current thread to a performance (big) core for stable measurements.
 *
 * @return true if successfully bound to a big core
 */
static inline bool ksu_bind_big_core() {
    // Read CPU max frequencies to identify big cores
    int max_freq = 0;
    int big_core = -1;
    int num_cpus = sysconf(_SC_NPROCESSORS_CONF);

    if (num_cpus < 2) return false;

    for (int i = 0; i < num_cpus && i < 16; i++) {
        char path[128];
        snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq", i);

        int fd = (int)syscall_raw(__NR_openat, AT_FDCWD, (long)path, O_RDONLY, 0);
        if (fd < 0) continue;

        char buf[32] = {0};
        ssize_t n = (ssize_t)syscall_raw(__NR_read, fd, (long)buf, sizeof(buf) - 1);
        syscall_raw(__NR_close, fd);

        if (n > 0) {
            int freq = atoi(buf);
            if (freq > max_freq) {
                max_freq = freq;
                big_core = i;
            }
        }
    }

    if (big_core >= 0) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(big_core, &cpuset);
        return sched_setaffinity(0, sizeof(cpu_set_t), &cpuset) == 0;
    }

    return false;
}

/**
 * Restore CPU affinity to allow scheduling on all cores
 */
static inline void ksu_restore_affinity() {
    int num_cpus = sysconf(_SC_NPROCESSORS_CONF);
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    for (int i = 0; i < num_cpus && i < 16; i++) {
        CPU_SET(i, &cpuset);
    }
    sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
}

/**
 * Collect timing samples for __NR_faccessat syscall.
 * faccessat(dirfd=-1, pathname=NULL, mode=-1, flags=0)
 * Intentionally invalid args for fast failure.
 *
 * @param samples Output array (must be at least KSU_NUM_SAMPLES * sizeof(int64_t))
 */
static inline void ksu_collect_faccessat_timing(int64_t* samples) {
    for (int i = 0; i < KSU_NUM_SAMPLES; i++) {
        uint64_t start = ksu_read_counter();
        // Call faccessat with invalid args - will fail immediately but still enters kernel
        // The hook overhead is incurred regardless of success/failure
        // Args: dirfd=-1, pathname=NULL, mode=-1, flags=0
        syscall_raw(__NR_faccessat, (long)-1, 0, (long)-1, 0);
        uint64_t end = ksu_read_counter();
        samples[i] = (int64_t)(end - start);
    }
}

/**
 * Collect timing samples for __NR_fchownat syscall.
 * fchownat(dirfd=-1, pathname=NULL, owner=0, group=0, flags=-1)
 * Intentionally invalid args for fast failure.
 * This syscall is NOT hooked by KernelSU, serves as baseline reference.
 *
 * @param samples Output array (must be at least KSU_NUM_SAMPLES * sizeof(int64_t))
 */
static inline void ksu_collect_fchownat_timing(int64_t* samples) {
    for (int i = 0; i < KSU_NUM_SAMPLES; i++) {
        uint64_t start = ksu_read_counter();
        // Call fchownat with invalid args - NOT hooked by KernelSU
        // Args: dirfd=-1, pathname=NULL, owner=0, group=0, flags=-1
        syscall_raw(__NR_fchownat, (long)-1, 0, 0, 0, (long)-1);
        uint64_t end = ksu_read_counter();
        samples[i] = (int64_t)(end - start);
    }
}

/**
 * Core KernelSU side-channel detection.
 *
 * 1. Bind to big core for stable measurements
 * 2. Allocate sample arrays for faccessat and fchownat
 * 3. Collect timing samples for both syscalls
 * 4. Sort both arrays (qsort) to reduce noise
 * 5. Compare sorted arrays element-by-element:
 *    Count anomalies where faccessat_time > fchownat_time + 1
 * 6. If anomaly count > threshold (7000/10000 = 70%), KSU detected
 *
 * @param out_anomaly_count  Output: number of anomalies detected
 * @param out_total_samples  Output: total samples compared
 * @return true if KernelSU hook detected (anomaly_count > threshold)
 */
static inline bool ksu_side_channel_check(int* out_anomaly_count, int* out_total_samples) {
    // Phase 1: Bind to big core for stable measurement
    bool bound = ksu_bind_big_core();

    // Phase 2: Allocate and zero timing arrays
    // Original uses malloc(80000) = 10000 * 8 bytes (int64_t)
    int64_t* faccessat_times = (int64_t*)malloc(KSU_NUM_SAMPLES * sizeof(int64_t));
    int64_t* fchownat_times = (int64_t*)malloc(KSU_NUM_SAMPLES * sizeof(int64_t));

    if (!faccessat_times || !fchownat_times) {
        free(faccessat_times);
        free(fchownat_times);
        if (out_anomaly_count) *out_anomaly_count = 0;
        if (out_total_samples) *out_total_samples = 0;
        if (bound) ksu_restore_affinity();
        return false;
    }

    memset(faccessat_times, 0, KSU_NUM_SAMPLES * sizeof(int64_t));
    memset(fchownat_times, 0, KSU_NUM_SAMPLES * sizeof(int64_t));

    // Phase 3: Collect timing samples
    ksu_collect_faccessat_timing(faccessat_times);
    ksu_collect_fchownat_timing(fchownat_times);

    // Phase 4: Sort both arrays to reduce extreme value impact
    qsort(faccessat_times, KSU_NUM_SAMPLES, sizeof(int64_t), ksu_compare_int64);
    qsort(fchownat_times, KSU_NUM_SAMPLES, sizeof(int64_t), ksu_compare_int64);

    // Phase 5: Compare sorted arrays element-by-element
    // Original uses NEON vectorized comparison for performance
    // Simplified equivalent:
    //   if (faccessat[i] > fchownat[i] + 1) anomaly++
    //
    // Rationale: Normally faccessat should be FASTER than fchownat
    // because faccessat is a simpler operation (just check access).
    // If faccessat is consistently SLOWER, it means there's a hook
    // adding overhead (KernelSU hooks faccessat, not fchownat).
    int anomaly_count = 0;
    for (int i = 0; i < KSU_NUM_SAMPLES; i++) {
        if (faccessat_times[i] > fchownat_times[i] + 1) {
            anomaly_count++;
        }
    }

    // Phase 6: Cleanup
    free(faccessat_times);
    free(fchownat_times);

    // Restore CPU affinity
    if (bound) ksu_restore_affinity();

    // Output results
    if (out_anomaly_count) *out_anomaly_count = anomaly_count;
    if (out_total_samples) *out_total_samples = KSU_NUM_SAMPLES;

    // Phase 7: Threshold check
    // Original: if (v24 > 0x1B58) => if (anomaly > 7000)
    return anomaly_count > KSU_ANOMALY_THRESHOLD;
}

#endif // LAUNCH_SYSCALL_WRAPPER_H
