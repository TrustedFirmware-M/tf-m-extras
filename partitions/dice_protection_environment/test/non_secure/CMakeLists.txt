#-------------------------------------------------------------------------------
# Copyright (c) 2023, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

cmake_policy(SET CMP0079 NEW)

target_sources(tfm_test_suite_extra_ns
    PRIVATE
        ../dpe_test.c
        dpe_ns_interface_testsuite.c
)

target_include_directories(tfm_test_suite_extra_ns
    PRIVATE
        ..
)

target_link_libraries(tfm_test_suite_extra_ns
    PRIVATE
        dpe_api_ns
)
