cmake_minimum_required(VERSION 3.2)

aux_source_directory(./ XED_FILES)

add_compile_options(-fgnu89-inline)
add_compile_options(-fPIC)
add_library(xed STATIC ${XED_FILES})

install(FILES ${PROJECT_BINARY_DIR}/src/xed/libxed.a DESTINATION 
              ${PROJECT_BINARY_DIR}/install/lib/)