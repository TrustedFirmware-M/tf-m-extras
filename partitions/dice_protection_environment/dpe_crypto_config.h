/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __DPE_CRYPTO_CONFIG_H__
#define __DPE_CRYPTO_CONFIG_H__

#include "psa/crypto.h"
#include "t_cose_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* DPE Crypto configuration for CDI derivation */
#define DPE_HASH_ALG      PSA_ALG_SHA_256
#define DPE_HASH_ALG_SIZE PSA_HASH_LENGTH(DPE_HASH_ALG)

#define DPE_CDI_KEY_TYPE  PSA_KEY_TYPE_DERIVE
#define DPE_CDI_KEY_ALG   PSA_ALG_HKDF(PSA_ALG_SHA_256)
#define DPE_CDI_KEY_BITS  256
#define DPE_CDI_KEY_USAGE PSA_KEY_USAGE_DERIVE

/* Below labels as per
 * https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/specification.md#attestation-cdi
 */
#define DPE_ATTEST_CDI_LABEL "CDI_Attest"
#define DPE_SEAL_CDI_LABEL   "CDI_Seal"

#define DPE_ATTEST_KEY_CURVE_TYPE PSA_ECC_FAMILY_SECP_R1
#define DPE_ATTEST_KEY_TYPE       PSA_KEY_TYPE_ECC_KEY_PAIR(DPE_ATTEST_KEY_CURVE_TYPE)
#define DPE_ATTEST_KEY_ALG        PSA_ALG_ECDSA(PSA_ALG_SHA_256)
#define DPE_ATTEST_KEY_BITS       PSA_BYTES_TO_BITS(PSA_HASH_LENGTH(PSA_ALG_SHA_256))
#define DPE_ATTEST_KEY_USAGE      PSA_KEY_USAGE_SIGN_HASH
#define DPE_ATTEST_PUB_KEY_SIZE   PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(DPE_ATTEST_KEY_BITS)

#define DPE_ATTEST_KEY_PAIR_LABEL "Key Pair"
#define DPE_EXTERNAL_LABEL_MAX_SIZE                  (20)

#define DPE_ATTEST_KEY_SALT {                                         \
    0x63, 0xB6, 0xA0, 0x4D, 0x2C, 0x07, 0x7F, 0xC1, 0x0F, 0x63, 0x9F, \
    0x21, 0xDA, 0x79, 0x38, 0x44, 0x35, 0x6C, 0xC2, 0xB0, 0xB4, 0x41, \
    0xB3, 0xA7, 0x71, 0x24, 0x03, 0x5C, 0x03, 0xF8, 0xE1, 0xBE, 0x60, \
    0x35, 0xD3, 0x1F, 0x28, 0x28, 0x21, 0xA7, 0x45, 0x0A, 0x02, 0x22, \
    0x2A, 0xB1, 0xB3, 0xCF, 0xF1, 0x67, 0x9B, 0x05, 0xAB, 0x1C, 0xA5, \
    0xD1, 0xAF, 0xFB, 0x78, 0x9C, 0xCD, 0x2B, 0x0B, 0x3B }

/* DPE Crypto configuration for Certificate creation and signature */
#define DPE_ID_LABEL "ID"
#define DPE_ID_SALT {                                                 \
    0xDB, 0xDB, 0xAE, 0xBC, 0x80, 0x20, 0xDA, 0x9F, 0xF0, 0xDD, 0x5A, \
    0x24, 0xC8, 0x3A, 0xA5, 0xA5, 0x42, 0x86, 0xDF, 0xC2, 0x63, 0x03, \
    0x1E, 0x32, 0x9B, 0x4D, 0xA1, 0x48, 0x43, 0x06, 0x59, 0xFE, 0x62, \
    0xCD, 0xB5, 0xB7, 0xE1, 0xE0, 0x0F, 0xC6, 0x80, 0x30, 0x67, 0x11, \
    0xEB, 0x44, 0x4A, 0xF7, 0x72, 0x09, 0x35, 0x94, 0x96, 0xFC, 0xFF, \
    0x1D, 0xB9, 0x52, 0x0B, 0xA5, 0x1C, 0x7B, 0x29, 0xEA };

/* As per RFC8152 */
#define DPE_T_COSE_ALG               T_COSE_ALGORITHM_ES256
#define DPE_T_COSE_KEY_TYPE_VAL       2  /* Elliptic Curve Keys w/ x and y-coordinate */
#define DPE_T_COSE_KEY_OPS_VAL        2  /* Key used for signature verification */
#define DPE_T_COSE_KEY_EC2_CURVE_VAL  1  /* NIST P-256 also known as secp256r1 */
#define DPE_T_COSE_KEY_ALG_VAL       -7  /* ECDSA w/ SHA-256 */

#ifdef __cplusplus
}
#endif

#endif /* __DPE_CRYPTO_CONFIG_H__ */
