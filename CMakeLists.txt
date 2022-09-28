cmake_minimum_required(VERSION 3.0)

project(read)

add_executable(read main.cpp)
target_link_libraries(read crypto ssl)

install(TARGETS read RUNTIME DESTINATION bin)
