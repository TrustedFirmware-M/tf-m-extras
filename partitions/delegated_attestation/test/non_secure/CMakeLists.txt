#-------------------------------------------------------------------------------
# Copyright (c) 2022-2024, Arm Limited. All rights reserved.
# Copyright (c) 2022 Cypress Semiconductor Corporation (an Infineon company)
# or an affiliate of Cypress Semiconductor Corporation. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

cmake_policy(SET CMP0079 NEW)

target_sources(tfm_test_suite_extra_ns
    PRIVATE
        ../../interface/src/tfm_delegated_attestation_api.c
        ../delegated_attest_test.c
        delegated_attest_ns_interface_testsuite.c
)

target_include_directories(tfm_test_suite_extra_ns
    PRIVATE
        ..
)

target_link_libraries(tfm_test_suite_extra_ns
    PRIVATE
        platform_region_defs
        psa_crypto_config
        qcbor
)
