#-------------------------------------------------------------------------------
# Copyright (c) 2023-2024, Arm Limited. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

cmake_policy(SET CMP0079 NEW)

target_sources(tfm_test_suite_extra_s
    PRIVATE
        ../dpe_certificate_decode.c
        ../dpe_derive_context_test.c
        ../dpe_certify_key_test.c
        ../dpe_test_data.c
        ../dpe_test_cmd_encode.c
        dpe_s_interface_testsuite.c
)

target_include_directories(tfm_test_suite_extra_s
    PRIVATE
        ..
)

target_link_libraries(tfm_test_suite_extra_s
    PRIVATE
        qcbor
        tfm_t_cose_s
)
