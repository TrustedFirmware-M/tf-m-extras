/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2022 Cypress Semiconductor Corporation (an Infineon company)
 * or an affiliate of Cypress Semiconductor Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "delegated_attest_test.h"

static struct test_t tfm_delegated_attest_ns_tests[] = {
    {&tfm_delegated_attest_test_1001, "TFM_NS_DELEGATED_ATTEST_TEST_1001",
     "Delegated Attestation Non-Secure Test 1001"},
    {&tfm_delegated_attest_test_1002, "TFM_NS_DELEGATED_ATTEST_TEST_1002",
     "Delegated Attestation Non-Secure Test 1002"},
    {&tfm_delegated_attest_test_1003, "TFM_NS_DELEGATED_ATTEST_TEST_1003",
     "Delegated Attestation Non-Secure Test 1003"},
};

void register_testsuite_extra_ns_interface(struct test_suite_t *p_test_suite)
{
    uint32_t list_size;

    list_size = (sizeof(tfm_delegated_attest_ns_tests) /
                 sizeof(tfm_delegated_attest_ns_tests[0]));

    set_testsuite("Delegated Attestation Non-Secure Tests"
                  "(TFM_NS_DELEGATED_ATTEST_TEST_1XXX)",
                  tfm_delegated_attest_ns_tests, list_size, p_test_suite);
}
