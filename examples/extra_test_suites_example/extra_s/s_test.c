/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 * Copyright (c) 2022 Cypress Semiconductor Corporation (an Infineon company)
 * or an affiliate of Cypress Semiconductor Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "extra_s_tests.h"

void s_test(struct test_result_t *ret)
{
    /* Add platform specific secure test suites code here. */

    ret->val = TEST_PASSED;
}

static struct test_t plat_s_t[] = {
    {&s_test, "TFM_S_EXTRA_TEST_1001",
     "Extra Secure test"},
};

void register_testsuite_extra_s_interface(struct test_suite_t *p_test_suite)
{
    /* Add platform init code here. */

    uint32_t list_size;

    list_size = (sizeof(plat_s_t) /
                 sizeof(plat_s_t[0]));

    set_testsuite("Extra Secure interface tests"
                  "(TFM_S_EXTRA_TEST_1XXX)",
                  plat_s_t, list_size, p_test_suite);
}
