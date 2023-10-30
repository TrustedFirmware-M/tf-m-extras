#-------------------------------------------------------------------------------
# Copyright (c) 2022-2023, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

if (NOT TFM_PARTITION_ADAC)
    return()
endif()

cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0079 NEW)

add_library(tfm_app_rot_partition_adac STATIC)

target_sources(tfm_app_rot_partition_adac
    PRIVATE
        adac.c
        adac_req_mngr.c
)

# Add the generated source files
target_sources(tfm_app_rot_partition_adac
    # The intermedia file defines the partition stack.
    PRIVATE
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/adac/auto_generated/intermedia_tfm_adac.c
)
target_sources(tfm_partitions
    # The load info file includes the static data of the partition.
    INTERFACE
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/adac/auto_generated/load_info_tfm_adac.c
)

# Set include directories
target_include_directories(tfm_app_rot_partition_adac
    PUBLIC
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/adac
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# Add dependency to the manifest_tool
add_dependencies(tfm_app_rot_partition_adac manifest_tool)

target_link_libraries(tfm_app_rot_partition_adac
    PRIVATE
        platform_s
        tfm_sprt
        trusted-firmware-m-psa-adac
)

############################ Secure API ########################################

set(INTERFACE_SRC_DIR            ${CMAKE_CURRENT_SOURCE_DIR}/interface/src)
set(INTERFACE_INC_DIR            ${CMAKE_CURRENT_SOURCE_DIR}/interface/include)

target_sources(tfm_sprt
    PRIVATE
        ${INTERFACE_SRC_DIR}/tfm_adac_api.c
)

target_include_directories(tfm_sprt
    PUBLIC
        ${INTERFACE_INC_DIR}
)

############################ Non-secure API ####################################

add_library(adac_api_ns INTERFACE)

target_sources(adac_api_ns
    INTERFACE
        ${INTERFACE_SRC_DIR}/tfm_adac_api.c
)

target_include_directories(adac_api_ns
    INTERFACE
        ${INTERFACE_INC_DIR}
)

############################ Partition Defs ####################################

target_link_libraries(tfm_partitions
    INTERFACE
        tfm_app_rot_partition_adac
)

target_compile_definitions(tfm_config
    INTERFACE
        TFM_PARTITION_ADAC
)

install(FILES       ${INTERFACE_SRC_DIR}/tfm_adac_api.c
        DESTINATION ${INSTALL_INTERFACE_SRC_DIR})

install(FILES       ${INTERFACE_INC_DIR}/tfm_adac_api.h
        DESTINATION ${INSTALL_INTERFACE_INC_DIR})
