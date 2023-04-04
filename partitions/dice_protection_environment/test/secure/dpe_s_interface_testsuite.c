/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dpe_test.h"

static struct test_t dpe_s_tests[] = {
    {&dpe_test_1001, "DPE_S_TEST_1001",
     "DPE DeriveChild API"},
    {&dpe_test_1002, "DPE_S_TEST_1002",
     "DPE CertifyKey API"},
};

void register_testsuite_extra_s_interface(struct test_suite_t *p_test_suite)
{
    uint32_t list_size;

    list_size = sizeof(dpe_s_tests) / sizeof(dpe_s_tests[0]);

    set_testsuite("DPE Secure Tests (DPE_S_TEST_1XXX)",
                  dpe_s_tests, list_size, p_test_suite);
}
