/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

/* This file describes the Delegated Attestation API */

#ifndef __TFM_DELEGATED_ATTESTATION_H__
#define __TFM_DELEGATED_ATTESTATION_H__

#include <stddef.h>
#include <stdint.h>
#include "psa/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Get a delegated attestation key (DAK).
 *
 * The aim of the delegated attestation key is to enable other SW components
 * within the system to sign an attestation token which is different than the
 * initial/platform token. The initial attestation token MUST contain the hash
 * of the public delegated key to make a cryptographical binding (hash lock)
 * between the key and the token.
 * The initial attestation token has two roles in this scenario:
 *  - Attest the device boot status and security lifecycle.
 *  - Attest the delegated attestation key.
 * The delegated attestation key is derived from a preprovisioned seed. The
 * input for the key derivation is the platform boot status. The system can be
 * attestated with the two tokens together.
 *
 * \param[in]  ecc_curve     The type of the elliptic curve to which the
 *                           requested attestation key belongs. Please check the
 *                           note section for limitations.
 * \param[in]  key_bits      The size of the requested attestation key, in bits.
 * \param[out] key_buf       Pointer to the buffer where the delegated
 *                           attestation key will be stored.
 * \param[in]  key_buf_size  Size of allocated buffer for the key, in bytes.
 * \param[out] key_size      Size of the key that has been returned, in bytes.
 * \param[in]  hash_algo     The hash algorithm that will be used later by the
 *                           owner of the requested delegated key for binding
 *                           it to the platform attestation token.
 *
 * \return Returns error code as specified in \ref psa_status_t
 *
 * \note   Currently, only the PSA_ECC_FAMILY_SECP_R1 curve type is supported.
 * \note   The delegated attestation key must be derived before requesting
 *         for the platform attestation token as they are cryptographically
 *         linked together.
 */
psa_status_t
tfm_delegated_attest_get_delegated_key(psa_ecc_family_t ecc_curve,
                                       uint32_t         key_bits,
                                       uint8_t         *key_buf,
                                       size_t           key_buf_size,
                                       size_t          *key_size,
                                       psa_algorithm_t  hash_algo);

/**
 * \brief Get platform attestation token
 *
 * \param[in]   dak_pub_hash       Pointer to buffer where the hash of the
 *                                 public DAK is stored.
 * \param[in]   dak_pub_hash_size  Size of the hash value, in bytes.
 * \param[out]  token_buf          Pointer to the buffer where the platform
 *                                 attestation token will be stored.
 * \param[in]   token_buf_size     Size of allocated buffer for token, in bytes.
 * \param[out]  token_size         Size of the token that has been returned, in
 *                                 bytes.
 *
 * \return Returns error code as specified in \ref psa_status_t
 *
 * \note    A delegated attestation key must be derived before requesting
 *          for the platform attestation token as they are cryptographically
 *          linked together. Otherwise, the token request will fail and the
 *          PSA_ERROR_INVALID_ARGUMENT code will be returned.
 */
psa_status_t
tfm_delegated_attest_get_token(const uint8_t *dak_pub_hash,
                               size_t         dak_pub_hash_size,
                               uint8_t       *token_buf,
                               size_t         token_buf_size,
                               size_t        *token_size);

#ifdef __cplusplus
}
#endif

#endif /* __TFM_DELEGATED_ATTESTATION_H__ */
