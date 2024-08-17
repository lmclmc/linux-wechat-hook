cmake_minimum_required(VERSION 3.2)

project(infector VERSION 1.4.0)

add_compile_options(-fPIC)

include_directories(src/)
include_directories(build/)
include_directories(${CMAKE_INCLUDE_PATH})

link_directories(${CMAKE_LIBRARY_PATH})

add_subdirectory(src/)
add_subdirectory(demo/)

configure_file(version.h.in version.h @ONLY)