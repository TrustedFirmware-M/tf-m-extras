#-------------------------------------------------------------------------------
# SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

if (NOT TFM_PARTITION_DTPM_CLIENT)
    return()
endif()

cmake_minimum_required(VERSION 3.21)
cmake_policy(SET CMP0079 NEW)

add_library(tfm_psa_rot_partition_dtpm_client STATIC)

target_sources(tfm_psa_rot_partition_dtpm_client
    PRIVATE
        dtpm_client.c
        dtpm_client_req_mngr.c
)

# The generated sources
target_sources(tfm_psa_rot_partition_dtpm_client
    PRIVATE
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/dtpm_client/auto_generated/intermedia_dtpm_client.c
)
target_sources(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/dtpm_client/auto_generated/load_info_dtpm_client.c
)

# Add dependency to the manifest_tool
add_dependencies(tfm_psa_rot_partition_dtpm_client manifest_tool)

# Set include directory
target_include_directories(tfm_psa_rot_partition_dtpm_client
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
    PUBLIC
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/dtpm_client
)

target_link_libraries(tfm_psa_rot_partition_dtpm_client
    PRIVATE
        platform_s
        psa_crypto_config
        tfm_config
        tfm_sprt
        tfm_log_headers
        tfm_helper_lib
)

########################### Secure API ########################################

set(INTERFACE_SRC_DIR            ${CMAKE_CURRENT_SOURCE_DIR}/interface)
set(INTERFACE_INC_DIR            ${CMAKE_CURRENT_SOURCE_DIR}/interface/include/)

target_sources(tfm_sprt
    PRIVATE
        ${INTERFACE_SRC_DIR}/dtpm_client_api.c
)

target_include_directories(tfm_sprt
    PUBLIC
        ${INTERFACE_INC_DIR}
)

############################ Partition Defs ####################################

target_link_libraries(tfm_partitions
    INTERFACE
        tfm_psa_rot_partition_dtpm_client
)


target_compile_definitions(tfm_config
    INTERFACE
    TFM_PARTITION_DTPM_CLIENT
)

install(FILES       ${INTERFACE_SRC_DIR}/dtpm_client_api.c
        DESTINATION ${INSTALL_INTERFACE_SRC_DIR})

install(FILES       ${INTERFACE_INC_DIR}/dtpm_client_api.h
        DESTINATION ${INSTALL_INTERFACE_INC_DIR})
