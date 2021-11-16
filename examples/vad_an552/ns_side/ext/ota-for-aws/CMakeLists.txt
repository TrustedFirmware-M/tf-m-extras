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

if ("${OTA_FOR_AWS_SRC_PATH}" STREQUAL "DOWNLOAD")
    find_package(Git)
    file(GLOB PATCH_FILES *.patch)

    FetchContent_Declare(ota_for_aws
        GIT_REPOSITORY https://github.com/aws/ota-for-aws-iot-embedded-sdk.git
        GIT_TAG 666241d
        PATCH_COMMAND ${GIT_EXECUTABLE} apply ${PATCH_FILES}
    )
    FetchContent_GetProperties(ota_for_aws)
    if (NOT ota_for_aws)
        FetchContent_Populate(ota_for_aws)
        set(OTA_FOR_AWS_SRC_PATH ${ota_for_aws_SOURCE_DIR} CACHE PATH "OTA for AWS (or DOWNLOAD to fetch automatically" FORCE)
    endif ()
endif ()
