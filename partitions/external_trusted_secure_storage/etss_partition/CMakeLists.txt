#-------------------------------------------------------------------------------
# Copyright (c) 2020-2022 Macronix. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

if (NOT TFM_PARTITION_EXTERNAL_TRUSTED_SECURE_STORAGE)
    return()
endif()

cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0079 NEW)

include(${CMAKE_CURRENT_SOURCE_DIR}/etss_config.cmake)
add_subdirectory(secureflash)
add_library(tfm_psa_rot_partition_etss STATIC)

target_include_directories(tfm_psa_rot_partition_etss
    PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/external_trusted_secure_storage
        ${CMAKE_CURRENT_SOURCE_DIR}/secureflash_fs
        ${CMAKE_CURRENT_SOURCE_DIR}/external_secure_flash
)

target_include_directories(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/external_trusted_secure_storage
)

target_sources(tfm_psa_rot_partition_etss
    PRIVATE
        etss_utils.c
        etss_req_mngr.c
        external_trusted_secure_storage.c
        external_secure_flash/etss_secureflash.c
        secureflash_fs/etss_flash_fs.c
        secureflash_fs/etss_flash_fs_dblock.c
        secureflash_fs/etss_flash_fs_mblock.c
)

# The generated sources
target_sources(tfm_psa_rot_partition_etss
    PRIVATE
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/external_trusted_secure_storage/auto_generated/intermedia_etss.c
)
target_sources(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/external_trusted_secure_storage/auto_generated/load_info_etss.c
)

target_link_libraries(tfm_psa_rot_partition_etss
    PRIVATE
        tfm_secure_api
        platform_s
        psa_interface
        hw_secure_flash
)
#Add compile definitions to a target
target_compile_definitions(tfm_psa_rot_partition_etss
    PRIVATE
        $<$<BOOL:${ETSS_CREATE_FLASH_LAYOUT}>:ETSS_CREATE_FLASH_LAYOUT>
        $<$<BOOL:${ETSS_VALIDATE_METADATA_FROM_FLASH}>:ETSS_VALIDATE_METADATA_FROM_FLASH>
        ETSS_MAX_ASSET_SIZE=${ETSS_MAX_ASSET_SIZE}
        ETSS_NUM_ASSETS=${ETSS_NUM_ASSETS}
        PROV_BLOB_LEN_MAX=${PROV_BLOB_LEN_MAX}
        $<$<BOOL:${ETSS_BUF_SIZE}>:ETSS_BUF_SIZE=${ETSS_BUF_SIZE}>
)

################ Display the configuration being applied #######################

message(STATUS "----------- Display storage configuration - start ------------")
message(STATUS "ETSS_CREATE_FLASH_LAYOUT is set to ${ETSS_CREATE_FLASH_LAYOUT}")
message(STATUS "ETSS_VALIDATE_METADATA_FROM_FLASH is set to ${ETSS_VALIDATE_METADATA_FROM_FLASH}")
message(STATUS "ETSS_MAX_ASSET_SIZE is set to ${ETSS_MAX_ASSET_SIZE}")
message(STATUS "ETSS_NUM_ASSETS is set to ${ETSS_NUM_ASSETS}")
if (${ETSS_BUF_SIZE})
    message(STATUS "ETSS_BUF_SIZE is set to ${ETSS_BUF_SIZE}")
else()
    message(STATUS "ETSS_BUF_SIZE is not set (defaults to ETSS_MAX_ASSET_SIZE)")
endif()

message(STATUS "----------- Display storage configuration - stop -------------")

############################ Secure API ########################################

target_sources(tfm_sprt
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/etss_secure_api.c
)

############################ Partition Defs ####################################

target_link_libraries(tfm_partitions
    INTERFACE
        tfm_psa_rot_partition_etss
)

target_compile_definitions(tfm_partition_defs
    INTERFACE
        TFM_PARTITION_EXTERNAL_TRUSTED_SECURE_STORAGE
)
