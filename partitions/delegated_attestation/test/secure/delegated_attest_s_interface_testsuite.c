/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "extra_tests_common.h"
#include "delegated_attest_test.h"


static int32_t tfm_delegated_attest_test(void)
{
    int32_t ret;

    TEST_LOG("  Delegated Attestation Secure Test 1001");
    ret = tfm_delegated_attest_test_1001();
    if (ret != EXTRA_TEST_SUCCESS) {
        TEST_LOG(" - FAILED\r\n");
        return ret;
    }
    TEST_LOG(" - PASSED\r\n");

    TEST_LOG("  Delegated Attestation Secure Test 1002");
    ret = tfm_delegated_attest_test_1002();
    if (ret != EXTRA_TEST_SUCCESS) {
        TEST_LOG(" - FAILED\r\n");
        return ret;
    }
    TEST_LOG(" - PASSED\r\n");

    TEST_LOG("  Delegated Attestation Secure Test 1003");
    ret = tfm_delegated_attest_test_1003();
    if (ret != EXTRA_TEST_SUCCESS) {
        TEST_LOG(" - FAILED\r\n");
        return ret;
    }
    TEST_LOG(" - PASSED\r\n");

    return ret;
}

/* Define test suite for delegated attestation service tests */
const struct extra_tests_t delegated_attestation_s_t = {
    .test_entry = tfm_delegated_attest_test,
    .expected_ret = EXTRA_TEST_SUCCESS,
};

int32_t extra_tests_init(struct extra_tests_t *internal_test_t)
{
    /* Add platform init code here. */

    return register_extra_tests(internal_test_t, &delegated_attestation_s_t);
}
