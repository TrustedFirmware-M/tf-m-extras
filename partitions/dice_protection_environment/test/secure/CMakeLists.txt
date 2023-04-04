#-------------------------------------------------------------------------------
# Copyright (c) 2023, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

cmake_policy(SET CMP0079 NEW)

target_sources(tfm_test_suite_extra_s
    PRIVATE
        ../dpe_test.c
        dpe_s_interface_testsuite.c
)

target_include_directories(tfm_test_suite_extra_s
    PRIVATE
        ..
)
