/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 * Copyright (c) 2022 Cypress Semiconductor Corporation (an Infineon company)
 * or an affiliate of Cypress Semiconductor Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "test_framework.h"

void ns_test(struct test_result_t *ret)
{
    /* Add platform specific non-secure test suites code here. */

    ret->val = TEST_PASSED;
}

static struct test_t plat_ns_t[] = {
    {&ns_test, "TFM_NS_EXTRA_TEST_1001",
     "Extra Non-Secure test"},
};

void register_testsuite_extra_ns_interface(struct test_suite_t *p_test_suite)
{
    /* Add platform init code here. */

    uint32_t list_size;

    list_size = (sizeof(plat_ns_t) /
                 sizeof(plat_ns_t[0]));

    set_testsuite("Extra Non-Secure interface tests"
                  "(TFM_NS_EXTRA_TEST_1XXX)",
                  plat_ns_t, list_size, p_test_suite);
}
