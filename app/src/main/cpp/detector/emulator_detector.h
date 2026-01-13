#ifndef LAUNCH_EMULATOR_DETECTOR_H
#define LAUNCH_EMULATOR_DETECTOR_H

#include <string>
#include <vector>

struct MultiLayerResult;

class EmulatorDetector {
public:
    // Emulator files to check
    static const std::vector<std::string>& getEmulatorFiles();

    // Emulator Build properties to check
    static const std::vector<std::string>& getEmulatorProperties();

    // Native layer detection
    static bool checkEmulatorFilesNative();
    static bool checkQemuNative();
    static bool checkGenyMotionNative();
    static bool checkNoxNative();
    static bool checkLdPlayerNative();
    static bool checkMemuNative();
    static bool checkBlueprintsNative();

    // Syscall layer detection
    static bool checkEmulatorFilesSyscall();
    static bool checkQemuSyscall();

    // Hardware detection (sensor count, battery, etc.)
    static bool checkSensorAnomalies();
    static bool checkBatteryAnomalies();

    // Combined detection
    static MultiLayerResult detectEmulator();
    static MultiLayerResult detectQemu();
    static MultiLayerResult detectVirtualMachine();
};

#endif // LAUNCH_EMULATOR_DETECTOR_H
