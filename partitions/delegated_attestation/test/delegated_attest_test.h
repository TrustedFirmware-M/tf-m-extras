/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2022 Cypress Semiconductor Corporation (an Infineon company)
 * or an affiliate of Cypress Semiconductor Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __DELEGATED_ATTEST_TEST_H__
#define __DELEGATED_ATTEST_TEST_H__

#include "test_framework.h"
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"
#include "psa/crypto_sizes.h"
#include "region_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \def PLATFORM_TOKEN_BUFF_SIZE
 *
 * \brief Size of platform attestation token buffer in bytes.
 */
#define PLATFORM_TOKEN_BUFF_SIZE    (PSA_INITIAL_ATTEST_TOKEN_MAX_SIZE)

/**
 * \def DELEGATED_ATTEST_KEY_MAX_SIZE
 *
 * \brief Maximum supported size of the derived delegated attestation key (DAK).
 */
#define DELEGATED_ATTEST_KEY_MAX_SIZE (PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(521))

/**
 * \def DELEGATED_ATTEST_KEY_ELLIPTIC_CURVE
 *
 * \brief Elliptic curve type to which the requested delegated attestation key
 *        belongs.
 */
#define DELEGATED_ATTEST_KEY_ELLIPTIC_CURVE    (PSA_ECC_FAMILY_SECP_R1)

/**
 * \def DELEGATED_ATTEST_KEY_BIT_SIZE
 *
 * \brief The bit size of the requested key
 */
#define DELEGATED_ATTEST_KEY_BIT_SIZE    (384)

/**
 * \def DELEGATED_ATTEST_KEY_HASH_ALGO
 *
 * \brief Algorithm used to calculate the hash of the public part of the DAK.
 */
#define DELEGATED_ATTEST_KEY_HASH_ALGO (PSA_ALG_SHA_256)

/**
 * \def DELEGATED_ATTEST_KEY_HASH_SIZE
 *
 * \brief The length of the DELEGATED_ATTEST_KEY_HASH_ALGO output.
 */
#define DELEGATED_ATTEST_KEY_HASH_SIZE (PSA_HASH_LENGTH(DELEGATED_ATTEST_KEY_HASH_ALGO))

/**
 * \brief Interface test: Test the platform attestation token API with valid
 *        and invalid inputs.
 *
 * \param[out] ret              Test result
 */
void tfm_delegated_attest_test_1001(struct test_result_t *ret);

/**
 * \brief Interface test: Test the delegated attestation key API with valid
 *        inputs.
 *
 * \param[out] ret              Test result
 */
void tfm_delegated_attest_test_1002(struct test_result_t *ret);

/**
 * \brief Interface test: Test the delegated attestation key API with invalid
 *        inputs.
 *
 * \param[out] ret              Test result
 */
void tfm_delegated_attest_test_1003(struct test_result_t *ret);

#ifdef __cplusplus
}
#endif

#endif /* __DELEGATED_ATTEST_TEST_H__ */
