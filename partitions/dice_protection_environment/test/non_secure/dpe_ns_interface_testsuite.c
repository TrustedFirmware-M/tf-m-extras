/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dpe_test.h"

static struct test_t dpe_ns_tests[] = {
    {&derive_rot_certificate_context, "DPE_NS_TEST_INIT",
     "DPE derive RoT context"},
    {&derive_context_api_test, "DPE_NS_TEST_1001",
     "DPE DeriveContext API"},
    {&certify_key_api_test, "DPE_NS_TEST_1002",
     "DPE CertifyKey API"},
};

void register_testsuite_extra_ns_interface(struct test_suite_t *p_test_suite)
{
    uint32_t list_size;

    list_size = sizeof(dpe_ns_tests) / sizeof(dpe_ns_tests[0]);

    set_testsuite("DPE Non-secure Tests (DPE_NS_TEST_1XXX)",
                  dpe_ns_tests, list_size, p_test_suite);
}
