cmake_minimum_required(VERSION 3.2)

add_subdirectory(infector/)
add_subdirectory(inject/)
add_subdirectory(target/)
add_subdirectory(xed/)

install(FILES ${PROJECT_BINARY_DIR}/src/inject/libinject.so DESTINATION 
              ${PROJECT_BINARY_DIR}/install/lib/)
install(FILES ${PROJECT_BINARY_DIR}/src/target/libtarget.a DESTINATION 
              ${PROJECT_BINARY_DIR}/install/lib/)
install(FILES ${PROJECT_BINARY_DIR}/src/infector/libinfector.a DESTINATION 
              ${PROJECT_BINARY_DIR}/install/lib/)
install(FILES inject/inject.h DESTINATION 
              ${PROJECT_BINARY_DIR}/install/include/inject/)
install(FILES target/targetopt.h DESTINATION 
              ${PROJECT_BINARY_DIR}/install/include/target/)
install(FILES infector/infector.h DESTINATION 
              ${PROJECT_BINARY_DIR}/install/include/infector/)
install(FILES infector/elf/elfopt.h DESTINATION 
              ${PROJECT_BINARY_DIR}/install/include/infector/)