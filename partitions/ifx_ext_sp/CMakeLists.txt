#-------------------------------------------------------------------------------
# (c) 2025-2026, Infineon Technologies AG, or an affiliate of Infineon
# Technologies AG. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

if (NOT IFX_EXT_SP)
    return()
endif()

cmake_minimum_required(VERSION 3.21)
cmake_policy(SET CMP0079 NEW)

################################ Configuration #################################

set(IFX_EXT_SP_STACK_SIZE   "0x600"   CACHE STRING  "IFX Extensions Partition stack size")

# When enabled, IFX Extensions Partition will make a call to register the user
# SRF module during its initialization. User module implementation can be
# provided in ifx_user_srf_module.c in the same directory as this
# CMakeLists.txt. Alternatively, user module implementation can be integrated
# through other means, such as modifying the partition sources directly or
# including the file in the build system elsewhere.
set(IFX_EXT_SP_REGISTER_USER_SRF_MODULE OFF CACHE BOOL "Whether to register the user SRF module in the IFX Extensions Partition.")

# Registering the user SRF module requires MTB SRF to be enabled
tfm_invalid_config(IFX_EXT_SP_REGISTER_USER_SRF_MODULE AND NOT IFX_MTB_SRF)

################################## Partition ###################################

add_library(tfm_psa_rot_partition_ifx_ext_sp STATIC)

target_sources(tfm_psa_rot_partition_ifx_ext_sp
    PRIVATE
        ifx_ext_sp_mngr.c
)

# The generated sources.
target_sources(tfm_psa_rot_partition_ifx_ext_sp
    PRIVATE
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/ifx_ext_sp/auto_generated/intermedia_ifx_ext_sp.c
)

target_sources(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/ifx_ext_sp/auto_generated/load_info_ifx_ext_sp.c
)

if (IFX_EXT_SP_REGISTER_USER_SRF_MODULE AND (EXISTS ${CMAKE_CURRENT_LIST_DIR}/ifx_user_srf_module.c))
    target_sources(tfm_psa_rot_partition_ifx_ext_sp
        PRIVATE
            ${CMAKE_CURRENT_LIST_DIR}/ifx_user_srf_module.c
    )
endif()

# Add dependency to the manifest_tool.
add_dependencies(tfm_psa_rot_partition_ifx_ext_sp manifest_tool)

set(INTERFACE_SRC_DIR            ${CMAKE_CURRENT_SOURCE_DIR}/interface/src)
set(INTERFACE_INC_DIR            ${CMAKE_CURRENT_SOURCE_DIR}/interface/include)

# Set include directories.
target_include_directories(tfm_psa_rot_partition_ifx_ext_sp
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
    PUBLIC
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/ifx_ext_sp
        ${INTERFACE_INC_DIR}
)

target_link_libraries(tfm_psa_rot_partition_ifx_ext_sp
    PRIVATE
        tfm_sprt
)

################################## Secure API ##################################

target_sources(tfm_sprt
    PRIVATE
        ${INTERFACE_SRC_DIR}/ifx_ext_sp_api.c
)

target_include_directories(tfm_sprt
    PUBLIC
        ${INTERFACE_INC_DIR}
)

################################ Partition Defs ################################

target_link_libraries(tfm_partitions
    INTERFACE
        tfm_psa_rot_partition_ifx_ext_sp
)

target_compile_definitions(tfm_config
    INTERFACE
        TFM_PARTITION_IFX_EXT_SP
        IFX_EXT_SP_STACK_SIZE=${IFX_EXT_SP_STACK_SIZE}
        $<$<BOOL:${IFX_EXT_SP_REGISTER_USER_SRF_MODULE}>:IFX_EXT_SP_REGISTER_USER_SRF_MODULE=1>
)

#################################### install ###################################

install(FILES       ${INTERFACE_SRC_DIR}/ifx_ext_sp_api.c
        DESTINATION ${INSTALL_INTERFACE_SRC_DIR})

install(FILES       ${INTERFACE_INC_DIR}/ifx_ext_sp_api.h
                    ${INTERFACE_INC_DIR}/ifx_ext_sp_defs.h
        DESTINATION ${INSTALL_INTERFACE_INC_DIR})
