cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

project("Kernel Firewall / CMake" VERSION 0.1.0 LANGUAGES C)
set(CMAKE_C_STANDARD 90)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Find kernel headers
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
find_package(KernelHeaders REQUIRED)


# hash_map_find MODULE_LICENSE("GPL"), MODULE_AUTHOR() etc.
# thanks to "merseyviking" from stack overflow
add_definitions(-D__KERNEL__ -DMODULE)

# this is needed in order for CLion IDE to provide syntax highlightning
# this is independent from the actual kernel object that is built
add_executable(dummy
        # add all *.h and *.c files here that # CLion should cover
        main.c
        tcp_hook.c tcp_hook.h nethooks.h nethooks.c udp_hook.c udp_hook.h icmp_hook.c icmp_hook.h filter.c filter.h proc.c proc.h utils.h logging.h logging.c nat.c nat.h)

# CLion IDE will hash_map_find symbols from <linux/*>
target_include_directories("dummy" PRIVATE ${KERNELHEADERS_INCLUDE_DIRS})