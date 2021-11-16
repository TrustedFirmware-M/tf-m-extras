#-------------------------------------------------------------------------------
# Copyright (c) 2021-2022, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
include(FetchContent)
set(FETCHCONTENT_QUIET FALSE)

if ("${OTA_PAL_PSA_SRC_PATH}" STREQUAL "DOWNLOAD")
    find_package(Git)
    file(GLOB PATCH_FILES *.patch)

    FetchContent_Declare(freertos_ota_pal_psa
        GIT_REPOSITORY https://github.com/Linaro/freertos-ota-pal-psa.git
        GIT_TAG 0b6db7d7cc0260fbb1e54a26ad6ff25cdcde3697
        PATCH_COMMAND ${GIT_EXECUTABLE} apply ${PATCH_FILES}
    )
    FetchContent_GetProperties(freertos_ota_pal_psa)
    if (NOT freertos_ota_pal_psa)
        FetchContent_Populate(freertos_ota_pal_psa)
        set(OTA_PAL_PSA_SRC_PATH ${freertos_ota_pal_psa_SOURCE_DIR} CACHE PATH "Path to freertos-ota-pal-psa (or DOWNLOAD to fetch automatically" FORCE)
    endif ()
endif ()
