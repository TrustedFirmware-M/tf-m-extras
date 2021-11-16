#-------------------------------------------------------------------------------
# Copyright (c) 2021-2022, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------
include(FetchContent)
set(FETCHCONTENT_QUIET FALSE)

if ("${PKCS11_PSA_SRC_PATH}" STREQUAL "DOWNLOAD")
    find_package(Git)
    file(GLOB PATCH_FILES *.patch)

    FetchContent_Declare(freertos_pkcs11_psa
        GIT_REPOSITORY https://github.com/Linaro/freertos-pkcs11-psa.git
        GIT_TAG 80292d24f4978891b0fd35feeb5f1d6f6f0fff06
        PATCH_COMMAND ${GIT_EXECUTABLE} apply ${PATCH_FILES}
    )
    FetchContent_GetProperties(freertos_pkcs11_psa)
    if (NOT freertos_pkcs11_psa)
        FetchContent_Populate(freertos_pkcs11_psa)
        set(PKCS11_PSA_SRC_PATH ${freertos_pkcs11_psa_SOURCE_DIR} CACHE PATH "Path to freertos-pkcs11-psa (or DOWNLOAD to fetch automatically" FORCE)
    endif ()
endif ()
