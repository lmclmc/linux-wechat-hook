cmake_minimum_required(VERSION 3.2)

aux_source_directory(./ INJECT_FILES)

add_library(inject SHARED ${INJECT_FILES}) 

target_link_libraries(inject 
    "-Wl,--whole-archive" #之后的库使用--whole-archive选项
    target
    pthread
    "-Wl,--no-whole-archive")  #之后的库不使用--whole-archive选项