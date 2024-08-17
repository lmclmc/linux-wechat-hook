cmake_minimum_required(VERSION 3.2)

set(VIRUS_FILES ./virus.cpp)
set(WECHAT_HOOK_FILES ./wechat_hook.cpp)


#add_executable(virus ${VIRUS_FILES})

add_library(X SHARED ${WECHAT_HOOK_FILES})

target_link_libraries(X lmcbase)
target_link_libraries(X target)

#target_link_libraries(virus lmcbase)
#target_link_libraries(virus infector)
#target_link_libraries(virus target)
#target_link_libraries(virus xed)

#install(FILES ${PROJECT_BINARY_DIR}/demo/virus PERMISSIONS OWNER_EXECUTE 
#              OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE WORLD_READ 
#              WORLD_WRITE DESTINATION ${PROJECT_BINARY_DIR}/install/demo/)