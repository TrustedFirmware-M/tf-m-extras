#-------------------------------------------------------------------------------
# Copyright (c) 2023-2024, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

cmake_policy(SET CMP0079 NEW)

target_sources(tfm_test_suite_extra_ns
    PRIVATE
        ../../interface/src/dpe_client.c
        ../../interface/src/dpe_cmd_encode.c
        ../dpe_certify_key_test.c
        ../dpe_derive_context_test.c
        ../dpe_test_data.c
        ../dpe_test_common.c
        dpe_ns_interface_testsuite.c
)

target_include_directories(tfm_test_suite_extra_ns
    PRIVATE
        ..
)

target_link_libraries(tfm_test_suite_extra_ns
    PRIVATE
        tfm_qcbor_ns
)
