#-------------------------------------------------------------------------------
# Copyright (c) 2020-2022, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.15)
cmake_policy(SET CMP0079 NEW)

# The name of the target is required to be of the pattern
# tfm_app_rot_partition_x or tfm_psa_rot_partition_x, as it affects how the
# linker script will lay the partition in memory.
add_library(tfm_app_rot_partition_dma350_unpriv STATIC)

# Add the source files generated by parse tools when building. The intermedia
# file defines the partition stack. The load info file includes the static data
# of the partition.
target_sources(tfm_app_rot_partition_dma350_unpriv
    PRIVATE
        tfm_dma350_example_partition.c
        dma350_lib/dma350_lib_unprivileged.c
        dma350_lib/dma350_privileged_config.c
        ${CMAKE_BINARY_DIR}/generated/auto_generated/intermedia_tfm_dma350_example_partition.c
)
target_sources(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/generated/auto_generated/load_info_tfm_dma350_example_partition.c
)

# Add dependency to the manifest_tool
add_dependencies(tfm_app_rot_partition_dma350_unpriv manifest_tool)

target_include_directories(tfm_app_rot_partition_dma350_unpriv
    PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/dma350_lib/
    PUBLIC
        ${CMAKE_BINARY_DIR}/generated
)

target_link_libraries(tfm_app_rot_partition_dma350_unpriv
    PRIVATE
        platform_s
        tfm_sprt
)

############################ Partition Defs ####################################

target_link_libraries(tfm_partitions
    INTERFACE
        tfm_app_rot_partition_dma350_unpriv
)
