cmake_minimum_required(VERSION 3.0)
project(avalokita)
include(CheckFunctionExists)

check_function_exists(prctl SYSTEM_PRCTL_FOUND)
if(NOT SYSTEM_PRCTL_FOUND)
    message(FATAL_ERROR "your os do not support prctl().")
endif()

set(CMAKE_C_FLAGS "-std=gnu89 -Wall -g")
set(VERSION_MAJOR 1)
set(VERSION_MINOR 0)
configure_file(src/config.h.in ${PROJECT_BINARY_DIR}/src/config.h)
add_subdirectory(src)
