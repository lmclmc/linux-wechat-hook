cmake_minimum_required(VERSION 3.2)

aux_source_directory(./ TARGET_FILES)

add_compile_options(-fPIC)
add_library(target STATIC ${TARGET_FILES})

target_link_libraries(target lmcbase)