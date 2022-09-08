/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __MEASURED_BOOT_TESTS_COMMON_H__
#define __MEASURED_BOOT_TESTS_COMMON_H__

#include "test_framework_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Interface test: Test Extend and Read Measurement API with valid
 *                        SHA256 measurement value and it should return without
 *                        any error.
 *
 * \param[out] ret        Test result
 */
void tfm_measured_boot_test_common_001(struct test_result_t *ret);

/**
 * \brief Interface test: Test Extend and Read Measurement API with valid
 *                        SHA512 measurement value and it should return without
 *                        any error.
 *
 * \param[out] ret        Test result
 */
void tfm_measured_boot_test_common_002(struct test_result_t *ret);

/**
 * \brief Interface test: Test Extend and Read Measurement API with invalid
 *                        measurement slot index and it should return
 *                        PSA_ERROR_INVALID_ARGUMENT.
 *
 * \param[out] ret        Test result
 */
void tfm_measured_boot_test_common_003(struct test_result_t *ret);

/**
 * \brief Interface test: Test Extend Measurement API with invalid measurement
 *                        value size and it should return
 *                        PSA_ERROR_INVALID_ARGUMENT.
 *
 * \param[out] ret        Test result
 */
void tfm_measured_boot_test_common_004(struct test_result_t *ret);

/**
 * \brief Interface test: Test Read Measurement API with invalid measurement
 *                        value size and it should return
 *                        PSA_ERROR_INVALID_ARGUMENT.
 *
 * \param[out] ret        Test result
 */
void tfm_measured_boot_test_common_005(struct test_result_t *ret);

/**
 * \brief Interface test: Test Extend Measurement API with invalid signer
 *                        id size and it should return
 *                        PSA_ERROR_INVALID_ARGUMENT.
 *
 * \param[out] ret        Test result
 */
void tfm_measured_boot_test_common_006(struct test_result_t *ret);

/**
 * \brief Interface test: Test Read Measurement API with invalid signer
 *                        id size and it should return
 *                        PSA_ERROR_INVALID_ARGUMENT.
 *
 * \param[out] ret        Test result
 */
void tfm_measured_boot_test_common_007(struct test_result_t *ret);

/**
 * \brief Interface test: Test Extend Measurement API with invalid version
 *                        size and it should return
 *                        PSA_ERROR_INVALID_ARGUMENT.
 *
 * \param[out] ret        Test result
 */
void tfm_measured_boot_test_common_008(struct test_result_t *ret);

/**
 * \brief Interface test: Test Read Measurement API with invalid version
 *                        size and it should return
 *                        PSA_ERROR_INVALID_ARGUMENT.
 *
 * \param[out] ret        Test result
 */
void tfm_measured_boot_test_common_009(struct test_result_t *ret);

/**
 * \brief Interface test: Test Extend Measurement API with invalid software
 *                        type size and it should return
 *                        PSA_ERROR_INVALID_ARGUMENT.
 *
 * \param[out] ret        Test result
 */
void tfm_measured_boot_test_common_010(struct test_result_t *ret);

/**
 * \brief Interface test: Test Read Measurement API with invalid software
 *                        type size and it should return
 *                        PSA_ERROR_INVALID_ARGUMENT.
 *
 * \param[out] ret        Test result
 */
void tfm_measured_boot_test_common_011(struct test_result_t *ret);

/**
 * \brief Interface test: Extend measurement api test for slot already locked
 *                        and it should return PSA_ERROR_BAD_STATE.
 *                        Note this test needs to be performed at the end since
 *                        once the slot is locked it will only be read-only for
 *                        further tests.
 *
 * \param[out] ret        Test result
 */
void tfm_measured_boot_test_common_012(struct test_result_t *ret);

/**
 * \brief Interface test: Test Extend Measurement API with different signer id
 *                        and it should return
 *                        PSA_ERROR_NOT_PERMITTED.
 *
 * \param[out] ret        Test result
 */
void tfm_measured_boot_test_common_013(struct test_result_t *ret);

#ifdef __cplusplus
}
#endif

#endif /* __MEASURED_BOOT_TESTS_COMMON_H__ */
