#-------------------------------------------------------------------------------
# Copyright (c) 2022, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

if (NOT TFM_PARTITION_DELEGATED_ATTESTATION)
    return()
endif()

cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0079 NEW)

add_library(tfm_app_rot_partition_delegated_attest STATIC)

target_sources(tfm_app_rot_partition_delegated_attest
    PRIVATE
        delegated_attest.c
        delegated_attest_req_mngr.c
)

# Add the generated source files
target_sources(tfm_app_rot_partition_delegated_attest
    # The intermedia file defines the partition stack.
    PRIVATE
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/delegated_attestation/auto_generated/intermedia_tfm_delegated_attestation.c
)
target_sources(tfm_partitions
    # The load info file includes the static data of the partition.
    INTERFACE
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/delegated_attestation/auto_generated/load_info_tfm_delegated_attestation.c
)

# Set include directories
target_include_directories(tfm_app_rot_partition_delegated_attest
    PUBLIC
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/delegated_attestation
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(tfm_app_rot_partition_delegated_attest
    PRIVATE
        $<$<BOOL:${DELEG_ATTEST_DUMP_TOKEN_AND_KEY}>:DELEG_ATTEST_DUMP_TOKEN_AND_KEY>
)

target_link_libraries(tfm_app_rot_partition_delegated_attest
    PRIVATE
        platform_s
        psa_interface
        tfm_sprt
        tfm_qcbor_s
        tfm_attestation_defs
)

############################ Secure API ########################################

set(INTERFACE_SRC_DIR            ${CMAKE_CURRENT_SOURCE_DIR}/interface/src)
set(INTERFACE_INC_DIR            ${CMAKE_CURRENT_SOURCE_DIR}/interface/include)

target_sources(tfm_sprt
    PRIVATE
        ${INTERFACE_SRC_DIR}/tfm_delegated_attestation_api.c
)

target_include_directories(tfm_sprt
    PUBLIC
        ${INTERFACE_INC_DIR}
)

############################ Non-secure API ####################################

add_library(delegated_attest_api_ns INTERFACE)

target_sources(delegated_attest_api_ns
    INTERFACE
        ${INTERFACE_SRC_DIR}/tfm_delegated_attestation_api.c
)

target_include_directories(delegated_attest_api_ns
    INTERFACE
        ${INTERFACE_INC_DIR}
)

############################ Partition Defs ####################################

target_link_libraries(tfm_partitions
    INTERFACE
        tfm_app_rot_partition_delegated_attest
)

target_compile_definitions(tfm_partition_defs
    INTERFACE
        TFM_PARTITION_DELEGATED_ATTESTATION
)

set(INSTALL_INTERFACE_SRC_DIR    ${TFM_INSTALL_PATH}/interface/src)
set(INSTALL_INTERFACE_INC_DIR    ${TFM_INSTALL_PATH}/interface/include)

install(FILES       ${INTERFACE_SRC_DIR}/tfm_delegated_attestation_api.c
        DESTINATION ${INSTALL_INTERFACE_SRC_DIR})

install(FILES       ${INTERFACE_INC_DIR}/tfm_delegated_attestation.h
                    ${INTERFACE_INC_DIR}/tfm_delegated_attest_defs.h
        DESTINATION ${INSTALL_INTERFACE_INC_DIR})
