#-------------------------------------------------------------------------------
# Copyright (c) 2021-2022, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
include(FetchContent)
set(FETCHCONTENT_QUIET FALSE)

# Needed to specfy submodule list
if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.16.0")
    cmake_policy(SET CMP0097 NEW)
endif()

if ("${FREERTOS_KERNEL_SRC_PATH}" STREQUAL "DOWNLOAD")
    find_package(Git)
    FetchContent_Declare(freertos_kernel
        GIT_REPOSITORY https://github.com/FreeRTOS/FreeRTOS-Kernel.git
        GIT_TAG 030e76681b981335ca4f25f0adce09612bf757a5
    )
    FetchContent_GetProperties(freertos_kernel)
    if (NOT freertos_kernel)
        FetchContent_Populate(freertos_kernel)
        set(FREERTOS_KERNEL_SRC_PATH ${freertos_kernel_SOURCE_DIR} CACHE PATH "Path to FreeRTOS kernel (or DOWNLOAD to fetch automatically" FORCE)
    endif ()
endif ()
