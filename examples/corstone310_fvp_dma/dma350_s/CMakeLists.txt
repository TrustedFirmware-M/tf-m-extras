#-------------------------------------------------------------------------------
# Copyright (c) 2021-2022, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

cmake_policy(SET CMP0079 NEW)

####################### Secure #################################################

add_library(dma350_test_s STATIC EXCLUDE_FROM_ALL)

target_sources(dma350_test_s
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/dma350_s_test.c
)

target_include_directories(dma350_test_s
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# DMA-350 test links tfm_test_suite_extra_common to use related interface
target_link_libraries(dma350_test_s
    PRIVATE
        tfm_sp_log_raw

        tfm_test_suite_extra_common
        platform_s
)

# The dma350_test_s library is linked by tfm_test_suite_extra_s
target_link_libraries(tfm_test_suite_extra_s
    PRIVATE
        dma350_test_s
)
