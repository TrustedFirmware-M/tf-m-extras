#-------------------------------------------------------------------------------
# Copyright (c) 2023-2024, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

cmake_policy(SET CMP0079 NEW)

####################### Secure #################################################

target_sources(tfm_test_suite_extra_ns
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/dma350_ns_test.c
        ${CONFIG_SPE_PATH}/platform/ext/target/arm/drivers/dma/dma350/dma350_ch_drv.c
        ${CONFIG_SPE_PATH}/platform/ext/target/arm/drivers/dma/dma350/dma350_drv.c
        ${CONFIG_SPE_PATH}/platform/ext/target/arm/drivers/dma/dma350/dma350_lib.c
        ${CONFIG_SPE_PATH}/platform/ext/target/arm/drivers/dma/dma350/dma350_checker_layer.c
        ${CONFIG_SPE_PATH}/platform/device/source/dma350_address_remap.c
)

target_include_directories(tfm_test_suite_extra_ns
    PRIVATE
        ${CONFIG_SPE_PATH}/platform/ext/target/arm/drivers/dma/dma350
)

target_compile_definitions(tfm_test_suite_extra_ns
    PRIVATE
        # Needed for DMA-350 library
        CMSIS_device_header=<corstone310.h>
)

target_link_libraries(tfm_test_suite_extra_ns
    PRIVATE
        platform_ns
        tfm_api_ns
        $<$<BOOL:${CONFIG_TFM_USE_TRUSTZONE}>:tfm_api_ns_tz>
)
