#-------------------------------------------------------------------------------
# Copyright (c) 2021, Arm Limited. All rights reserved.
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

if ("${ARM_ENDPOINTAI_SRC_PATH}" STREQUAL "DOWNLOAD")
    find_package(Git)

    FetchContent_Declare(arm_endpoint_ai
        GIT_REPOSITORY https://github.com/ARM-software/EndpointAI.git
        GIT_TAG 80c5b64888ba9f5d26defb4db0ef178786ff65b9
    )
    FetchContent_GetProperties(arm_endpoint_ai)
    if (NOT arm_endpoint_ai)
        FetchContent_Populate(arm_endpoint_ai)
        set(ARM_ENDPOINTAI_SRC_PATH ${arm_endpoint_ai_SOURCE_DIR} CACHE PATH "Path to Arm's EndpointAI repository (or DOWNLOAD to fetch automatically" FORCE)
    endif ()
endif ()
