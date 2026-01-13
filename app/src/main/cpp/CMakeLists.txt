# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html.
# For more examples on how to use CMake, see https://github.com/android/ndk-samples.

# Sets the minimum CMake version required for this project.
cmake_minimum_required(VERSION 3.22.1)

# Declares the project name.
project("launch")

# Creates and names a library, sets it as either STATIC or SHARED, and provides
# the relative paths to its source code.
add_library(${CMAKE_PROJECT_NAME} SHARED
        # Main JNI entry
        native-lib.cpp
        # Detector implementations
        detector/root_detector.cpp
        detector/hook_detector.cpp
        detector/emulator_detector.cpp
        detector/debug_detector.cpp
        detector/integrity_detector.cpp
)

# Include directories
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/detector
        ${CMAKE_SOURCE_DIR}/syscall
)

# Specifies libraries CMake should link to your target library.
target_link_libraries(${CMAKE_PROJECT_NAME}
        android
        log
)

# Compiler flags for optimization and security
target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE
        -Wall
        -Wextra
        -fvisibility=hidden
        -fstack-protector-strong
)
