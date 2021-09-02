/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "ns_test.h"

const struct extra_tests_t plat_ns_t = {
    .test_entry = ns_test,
    .expected_ret = EXTRA_TEST_SUCCESS
};

int32_t ns_test(void)
{
    /* Add platform specific non-secure test suites code here. */

    return EXTRA_TEST_SUCCESS;
}

int32_t extra_tests_init(struct extra_tests_t *internal_test_t)
{
    /* Add platform init code here. */

    return register_extra_tests(internal_test_t, &plat_ns_t);
}
