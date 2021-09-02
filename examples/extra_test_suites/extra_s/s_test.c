/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "s_test.h"

const struct extra_tests_t plat_s_t = {
    .test_entry = s_test,
    .expected_ret = EXTRA_TEST_SUCCESS
};

int32_t s_test(void)
{
    /* Add platform specific secure test suites code here. */

    return EXTRA_TEST_SUCCESS;
}

int32_t extra_tests_init(struct extra_tests_t *internal_test_t)
{
    /* Add platform init code here. */

    return register_extra_tests(internal_test_t, &plat_s_t);
}
