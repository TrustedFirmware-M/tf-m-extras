#-------------------------------------------------------------------------------
# Copyright (c) 2023, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

cmake_policy(SET CMP0079 NEW)

####################### Secure #################################################

target_sources(tfm_test_suite_extra_ns
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/dma350_ns_test.c
        ${CMAKE_SOURCE_DIR}/platform/ext/target/arm/mps3/corstone310/fvp/native_drivers/dma350_ch_drv.c
        ${CMAKE_SOURCE_DIR}/platform/ext/target/arm/mps3/corstone310/fvp/native_drivers/dma350_drv.c
        ${CMAKE_SOURCE_DIR}/platform/ext/target/arm/mps3/corstone310/fvp/libraries/dma350_lib.c
        ${CMAKE_SOURCE_DIR}/platform/ext/target/arm/mps3/corstone310/fvp/libraries/dma350_checker_layer.c
        ${CMAKE_SOURCE_DIR}/platform/ext/target/arm/mps3/corstone310/fvp/device/source/dma350_address_remap.c
)

target_include_directories(tfm_test_suite_extra_ns
    PRIVATE
        ${CMAKE_SOURCE_DIR}/platform/ext/target/arm/mps3/corstone310/fvp/native_drivers
        ${CMAKE_SOURCE_DIR}/platform/ext/target/arm/mps3/corstone310/fvp/libraries
)

target_compile_definitions(tfm_test_suite_extra_ns
    PRIVATE
        # Needed for DMA-350 library
        CMSIS_device_header=<corstone310.h>
)

target_link_libraries(tfm_test_suite_extra_ns
    PRIVATE
        platform_ns
)
