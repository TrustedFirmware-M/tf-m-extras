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

if ("${AMAZON_FREERTOS_SRC_PATH}" STREQUAL "DOWNLOAD")
    find_package(Git)

    FetchContent_Declare(amazon_freertos
        GIT_REPOSITORY https://github.com/aws/amazon-freertos.git
        GIT_TAG 202107.00
        GIT_SUBMODULES "libraries/freertos_plus/standard/freertos_plus_tcp
                        libraries/coreMQTT
                        libraries/coreMQTT-Agent
                        libraries/abstractions/backoff_algorithm
                        libraries/abstractions/pkcs11/corePKCS11
                        libraries/3rdparty/mbedtls"
    )
    FetchContent_GetProperties(amazon_freertos)
    if (NOT amazon_freertos)
        FetchContent_Populate(amazon_freertos)
        set(AMAZON_FREERTOS_SRC_PATH ${amazon_freertos_SOURCE_DIR} CACHE PATH "Path to Amazon FreeRTOS (or DOWNLOAD to fetch automatically" FORCE)
    endif ()
endif ()
