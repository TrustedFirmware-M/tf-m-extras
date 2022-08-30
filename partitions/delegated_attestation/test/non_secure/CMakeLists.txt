#-------------------------------------------------------------------------------
# Copyright (c) 2022, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

cmake_policy(SET CMP0079 NEW)

add_library(tfm_test_suite_delegated_attestation_ns STATIC EXCLUDE_FROM_ALL)

target_sources(tfm_test_suite_delegated_attestation_ns
    PRIVATE
        ../delegated_attest_test.c
        delegated_attest_ns_interface_testsuite.c
)

target_include_directories(tfm_test_suite_delegated_attestation_ns
    PRIVATE
        ..
)

target_link_libraries(tfm_test_suite_delegated_attestation_ns
    PRIVATE
        tfm_test_framework_ns
        tfm_test_suite_extra_common
        platform_region_defs
        delegated_attest_api_ns
)

target_link_libraries(tfm_test_suite_extra_ns
    PRIVATE
        tfm_test_suite_delegated_attestation_ns
)
