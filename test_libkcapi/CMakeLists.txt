###  AUTHOR: wangshijie  ###
CMAKE_MINIMUM_REQUIRED (VERSION 3.5)
PROJECT (test_libkcapi)

SET(TARGET_TYPE arm)

IF(${TARGET_TYPE} STREQUAL "arm")
        MESSAGE(STATUS "========== The target is for arm, so let's cross-compile ==========")
        SET(CMAKE_SYSTEM_NAME Linux)
        SET(CMAKE_CROSSCOMPILING TRUE)
        SET(CMAKE_SYSTEM_PROCESSOR arm)

        # 1. set crosscompile path
        SET(TOOLSCHAIN_PATH "/home/hp/toolschain/gcc-linaro-7.4.1-2019.02-x86_64_aarch64-linux-gnu/")
        SET(TOOLCHAIN_HOST "${TOOLSCHAIN_PATH}bin/aarch64-linux-gnu")
        SET(TOOLSCHAIN_INCLUDE_PATH "${TOOLSCHAIN_PATH}/aarch64-linux-gnu/libc/usr/include")
        MESSAGE(STATUS "TOOLCHAIN_HOST: ${TOOLCHAIN_HOST}")
        SET(CMAKE_SYSROOT "/home/hp/toolschain/sysroot-glibc-linaro-2.25-2019.02-aarch64-linux-gnu")
        #SET(CMAKE_SYSROOT "/home/hp/toolschain/gcc-linaro-7.4.1-2019.02-x86_64_aarch64-linux-gnu/aarch64-linux-gnu/libc")

        #set(CMAKE_FIND_ROOT_PATH "${SYSROOT_PATH}" "${CMAKE_PREFIX_PATH}" "${TOOLSCHAIN_PATH}")
        SET(CMAKE_FIND_ROOT_PATH  "${CMAKE_PREFIX_PATH}" "${TOOLSCHAIN_PATH}")

        SET(CMAKE_C_COMPILER "${TOOLCHAIN_HOST}-gcc")
        SET(CMAKE_CXX_COMPILER "${TOOLCHAIN_HOST}-g++")

ELSE()
        MESSAGE(STATUS "========== This is for X86, use GCC ==========")
ENDIF()

# 2. set CFLAGS
SET(CMAKE_C_FLAGS "-O0 -DKCAPI_PATCHLEVEL=0")
SET(CMAKE_CXX_FLAGS "-O0 -ggdb")

ADD_SUBDIRECTORY(lib)
ADD_SUBDIRECTORY(src)