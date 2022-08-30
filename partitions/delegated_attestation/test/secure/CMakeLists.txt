#-------------------------------------------------------------------------------
# Copyright (c) 2022, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

cmake_policy(SET CMP0079 NEW)

add_library(tfm_test_suite_delegated_attestation_s STATIC EXCLUDE_FROM_ALL)

target_sources(tfm_test_suite_delegated_attestation_s
    PRIVATE
        ../delegated_attest_test.c
        delegated_attest_s_interface_testsuite.c
)

target_include_directories(tfm_test_suite_delegated_attestation_s
    PRIVATE
        ..
)

target_link_libraries(tfm_test_suite_delegated_attestation_s
    PRIVATE
        tfm_test_framework_s
        tfm_sprt #for public header: tfm_delegated_attestation.h
        tfm_test_suite_extra_common
        platform_region_defs
)

target_link_libraries(tfm_test_suite_extra_s
    PRIVATE
        tfm_test_suite_delegated_attestation_s
)
