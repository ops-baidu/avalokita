cmake_minimum_required(VERSION 2.8)
project(avalokita)

set(CMAKE_C_FLAGS "-D__RELATIVE_PATH__='\"$(subst ${CMAKE_SOURCE_DIR}/,,$(abspath $<))\"'")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu89 -Wall -Wextra -g")
configure_file(src/config.h.in ${PROJECT_BINARY_DIR}/src/config.h)
add_subdirectory(src)
