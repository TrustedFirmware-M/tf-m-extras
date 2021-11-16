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

if ("${CMSIS_5_SRC_PATH}" STREQUAL "DOWNLOAD")
    find_package(Git)

    FetchContent_Declare(cmsis_5
        GIT_REPOSITORY https://github.com/ARM-software/CMSIS_5.git
        GIT_TAG 5.8.0
    )
    FetchContent_GetProperties(cmsis_5)
    if (NOT cmsis_5)
        FetchContent_Populate(cmsis_5)
        set(CMSIS_5_SRC_PATH ${cmsis_5_SOURCE_DIR} CACHE PATH "Path to CMSIS_5 repository (or DOWNLOAD to fetch automatically" FORCE)
    endif ()
endif ()
