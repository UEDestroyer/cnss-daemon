cmake_minimum_required(VERSION 3.16)
project(cnss_daemon LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(cnss-daemon
    src/main.cpp
    src/daemon.cpp
    src/netlink.cpp
    src/qmi.cpp
    src/unix_socket.cpp
    src/logger.cpp
    src/event_registry.cpp
    src/platform.cpp
    src/neighbor_watch.cpp
)

target_include_directories(cnss-daemon PRIVATE include)
target_compile_options(cnss-daemon PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
target_link_libraries(cnss-daemon PRIVATE pthread dl)

install(TARGETS cnss-daemon RUNTIME DESTINATION bin)
