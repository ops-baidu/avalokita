cmake_minimum_required(VERSION 3.0)
project(avalokita)

set(CMAKE_C_FLAGS "-std=gnu89 -Wall -Wextra -g")
set(VERSION_MAJOR 1)
set(VERSION_MINOR 0)
configure_file(src/config.h.in ${PROJECT_BINARY_DIR}/src/config.h)
add_subdirectory(src)
