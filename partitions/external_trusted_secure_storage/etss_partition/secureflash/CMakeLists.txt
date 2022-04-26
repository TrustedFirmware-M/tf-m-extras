#-------------------------------------------------------------------------------
# Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.15)

cmake_policy(SET CMP0079 NEW)

add_library(hw_secure_flash STATIC)

add_subdirectory(${SECURE_FLASH_TYPE})

target_sources(hw_secure_flash
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/secureflash_common/secureflash_common.c
        secureflash.c
)

target_include_directories(hw_secure_flash
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/secureflash_common
)

#Add compile definitions to a target
target_compile_definitions(hw_secure_flash
    PRIVATE
        ETSS_SF_WRITE_BUF_SIZE=${ETSS_SF_ASSET_BUF_SIZE}
        ETSS_SF_READ_BUF_SIZE=${ETSS_SF_ASSET_BUF_SIZE}
        CRYPTO_ASSET_SIZE=${ETSS_SF_ASSET_BUF_SIZE}
)

target_link_libraries(hw_secure_flash
    PRIVATE
        psa_interface
        platform_s
        tfm_utilities
)
