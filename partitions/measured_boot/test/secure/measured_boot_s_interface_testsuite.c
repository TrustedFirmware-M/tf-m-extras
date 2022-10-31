/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2022 Cypress Semiconductor Corporation (an Infineon company)
 * or an affiliate of Cypress Semiconductor Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "test_framework_helpers.h"
#include "../measured_boot_tests_common.h"
#include "../measured_boot_common.h"

static struct test_t tfm_measured_boot_s_tests[] = {
    {&tfm_measured_boot_test_common_001, "TFM_S_MEASURED_BOOT_TEST_1001",
     "Extend and Read Measurement - valid input SHA256 measurement value"},
    {&tfm_measured_boot_test_common_002, "TFM_S_MEASURED_BOOT_TEST_1002",
     "Extend and Read Measurement - valid input SHA512 measurement value"},
    {&tfm_measured_boot_test_common_003, "TFM_S_MEASURED_BOOT_TEST_1003",
     "Extend and Read Measurement - invalid slot index"},
    {&tfm_measured_boot_test_common_004, "TFM_S_MEASURED_BOOT_TEST_1004",
     "Extend Measurement - invalid measurement value size"},
    {&tfm_measured_boot_test_common_005, "TFM_S_MEASURED_BOOT_TEST_1005",
     "Read Measurement - invalid input measurement buffer size"},
    {&tfm_measured_boot_test_common_006, "TFM_S_MEASURED_BOOT_TEST_1006",
     "Extend Measurement - invalid signer id size"},
    {&tfm_measured_boot_test_common_007, "TFM_S_MEASURED_BOOT_TEST_1007",
     "Read Measurement - invalid input signer id buffer size"},
    {&tfm_measured_boot_test_common_008, "TFM_S_MEASURED_BOOT_TEST_1008",
     "Extend Measurement - invalid version size"},
    {&tfm_measured_boot_test_common_009, "TFM_S_MEASURED_BOOT_TEST_1009",
     "Read Measurement - invalid input version buffer size"},
    {&tfm_measured_boot_test_common_010, "TFM_S_MEASURED_BOOT_TEST_1010",
     "Extend Measurement - invalid input software type buffer size"},
    {&tfm_measured_boot_test_common_011, "TFM_S_MEASURED_BOOT_TEST_1011",
     "Read Measurement - invalid software type size"},
    {&tfm_measured_boot_test_common_012, "TFM_S_MEASURED_BOOT_TEST_1012",
     "Extend Measurement - S unlock test"},
    {&tfm_measured_boot_test_common_013, "TFM_S_MEASURED_BOOT_TEST_1013",
     "Extend Measurement - different signer id"}
};

void register_testsuite_extra_s_interface(struct test_suite_t *p_test_suite)
{
    uint32_t list_size;

    list_size = (sizeof(tfm_measured_boot_s_tests) /
                 sizeof(tfm_measured_boot_s_tests[0]));

    set_testsuite("Measured boot partition secure test suite"
                  "(TFM_S_MEASURED_BOOT_TEST_1XXX)",
                  tfm_measured_boot_s_tests, list_size, p_test_suite);
}
