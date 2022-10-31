#-------------------------------------------------------------------------------
# Copyright (c) 2021-2022, Arm Limited. All rights reserved.
# Copyright (c) 2022 Cypress Semiconductor Corporation (an Infineon company)
# or an affiliate of Cypress Semiconductor Corporation. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

cmake_policy(SET CMP0079 NEW)

####################### Secure #################################################

target_sources(tfm_test_suite_extra_s
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/dma350_s_test.c
)

target_link_libraries(tfm_test_suite_extra_s
    PRIVATE
        tfm_sprt
)
