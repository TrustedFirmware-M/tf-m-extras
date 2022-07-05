#-------------------------------------------------------------------------------
# Copyright (c) 2022, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

if (NOT TFM_PARTITION_MEASURED_BOOT)
    return()
endif()

cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0079 NEW)

# The name of the target is required to be of the pattern
# tfm_app_rot_partition_x or tfm_psa_rot_partition_x, as it affects how the
# linker script will lay the partition in memory.
add_library(tfm_psa_rot_partition_measured_boot STATIC)

target_sources(tfm_psa_rot_partition_measured_boot
    PRIVATE
        measured_boot.c
        measured_boot_req_mngr.c
        measured_boot_utils.c
)

# The generated sources
target_sources(tfm_psa_rot_partition_measured_boot
    PRIVATE
        $<$<BOOL:${TFM_PSA_API}>:
            ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/measured_boot/auto_generated/intermedia_tfm_measured_boot.c>
)
target_sources(tfm_partitions
    INTERFACE
        $<$<BOOL:${TFM_PSA_API}>:
            ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/measured_boot/auto_generated/load_info_tfm_measured_boot.c>
)

# Set include directory
target_include_directories(tfm_psa_rot_partition_measured_boot
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/measured_boot
)


target_link_libraries(tfm_psa_rot_partition_measured_boot
    PRIVATE
        tfm_secure_api
        psa_interface
        platform_s
        tfm_sprt
)

if(${MEASURED_BOOT_HASH_ALG} STREQUAL "PSA_ALG_SHA_512")
    set(MEASUREMENT_VALUE_SIZE 64)
elseif(${MEASURED_BOOT_HASH_ALG} STREQUAL "PSA_ALG_SHA_256")
    set(MEASUREMENT_VALUE_SIZE 32)
else()
    message(FATAL_ERROR "Unknown hash algorithm")
endif()

target_compile_definitions(tfm_psa_rot_partition_measured_boot
    PUBLIC
        TFM_MEASURED_BOOT_HASH_ALG=${MEASURED_BOOT_HASH_ALG}
        MEASUREMENT_VALUE_SIZE=${MEASUREMENT_VALUE_SIZE}
        $<$<BOOL:${CONFIG_TFM_BOOT_STORE_MEASUREMENTS}>:CONFIG_TFM_BOOT_STORE_MEASUREMENTS>
)

############################ Secure API ########################################

set(INTERFACE_SRC_DIR            ${CMAKE_CURRENT_SOURCE_DIR}/interface/src)
set(INTERFACE_INC_DIR            ${CMAKE_CURRENT_SOURCE_DIR}/interface/include)

target_sources(tfm_sprt
    INTERFACE
        ${INTERFACE_SRC_DIR}/measured_boot_api.c
)

target_include_directories(tfm_sprt
    PUBLIC
        ${INTERFACE_INC_DIR}
)

# The veneers give warnings about not being properly declared so they get hidden
# to not overshadow _real_ warnings.
set_source_files_properties(measured_boot_api.c
    PROPERTIES
        COMPILE_FLAGS -Wno-implicit-function-declaration
)

############################ Partition Defs ####################################

target_link_libraries(tfm_partitions
    INTERFACE
        tfm_psa_rot_partition_measured_boot
)

target_compile_definitions(tfm_partition_defs
    INTERFACE
        TFM_PARTITION_MEASURED_BOOT
)

set(INSTALL_INTERFACE_SRC_DIR    ${TFM_INSTALL_PATH}/interface/src)
set(INSTALL_INTERFACE_INC_DIR    ${TFM_INSTALL_PATH}/interface/include)

install(FILES       ${INTERFACE_SRC_DIR}/measured_boot_api.c
        DESTINATION ${INSTALL_INTERFACE_SRC_DIR})

install(FILES       ${INTERFACE_INC_DIR}/measured_boot_api.h
                    ${INTERFACE_INC_DIR}/measured_boot_defs.h
        DESTINATION ${INSTALL_INTERFACE_INC_DIR})