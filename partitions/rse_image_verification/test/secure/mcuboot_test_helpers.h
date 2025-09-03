/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 */

#ifndef __MCUBOOT_TEST_HELPERS_H__
#define __MCUBOOT_TEST_HELPERS_H__

#include "rse_image_verification_defs.h"
#include "test_framework.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Test configuration structure for MCUBoot tests */
struct riv_mcuboot_test_config {
    bool corrupt_signature;
    bool corrupt_public_key;
    bool bad_nv_counter;
    uint32_t num_chains;
    bool must_be_signed;
    bool corrupt_verification_structure;
    enum rse_verification_service_err_t expected_ret_val;
};

void execute_mcuboot_test(
    struct test_result_t *ret, const struct riv_mcuboot_test_config *config,
    struct rse_image_verification_boot_measurement_t *boot_measurement);

#ifdef __cplusplus
}
#endif
#endif /* __MCUBOOT_TEST_HELPERS_H__ */
