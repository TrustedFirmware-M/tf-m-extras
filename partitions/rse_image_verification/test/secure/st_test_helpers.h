/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 */

#ifndef __ST_TEST_HELPERS_H__
#define __ST_TEST_HELPERS_H__

#include <stdbool.h>
#include <stdint.h>

#include "rse_image_verification_defs.h"
#include "test_framework.h"

#ifdef __cplusplus
extern "C" {
#endif

struct riv_st_test_config {
    bool corrupt_signature;
    bool corrupt_public_key;
    bool corrupt_image_hash;
    uint32_t num_chains;
    enum rse_verification_service_err_t expected_ret_val;
};

void execute_st_test(struct test_result_t *ret,
                     const struct riv_st_test_config *config,
                     struct rse_image_verification_boot_measurement_t *boot_measurement);

#ifdef __cplusplus
}
#endif
#endif /* __ST_TEST_HELPERS_H__ */
