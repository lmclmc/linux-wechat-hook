cmake_minimum_required(VERSION 3.2)

FILE(GLOB_RECURSE INFECTOR_FILES ./*.cpp)
#add_compile_options(-fPIC)
add_library(infector STATIC ${INFECTOR_FILES})

target_link_libraries(infector xed)