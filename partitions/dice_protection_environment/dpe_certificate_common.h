/*
 * Copyright (c) 2023-2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __DPE_CERTIFICATE_COMMON_H__
#define __DPE_CERTIFICATE_COMMON_H__

#ifdef __cplusplus
extern "C" {
#endif

/* As per RFC8152 */
#define DPE_CERT_LABEL_COSE_KEY_TYPE      (1)
#define DPE_CERT_LABEL_COSE_KEY_ID        (2)
#define DPE_CERT_LABEL_COSE_KEY_ALG       (3)
#define DPE_CERT_LABEL_COSE_KEY_OPS       (4)
#define DPE_CERT_LABEL_COSE_KEY_EC2_CURVE (-1)
#define DPE_CERT_LABEL_COSE_KEY_EC2_X     (-2)
#define DPE_CERT_LABEL_COSE_KEY_EC2_Y     (-3)

/* As per RFC8392 */
#define DPE_CERT_LABEL_ISSUER                    (1)
#define DPE_CERT_LABEL_SUBJECT                   (2)

/* As per Open Profile for DICE specification */
#define DPE_CERT_LABEL_RANGE_BASE                (-4670545)
#define DPE_CERT_LABEL_CODE_HASH                 (DPE_CERT_LABEL_RANGE_BASE - 0)
#define DPE_CERT_LABEL_CODE_DESCRIPTOR           (DPE_CERT_LABEL_RANGE_BASE - 1)
#define DPE_CERT_LABEL_CONFIGURATION_HASH        (DPE_CERT_LABEL_RANGE_BASE - 2)
#define DPE_CERT_LABEL_CONFIGURATION_DESCRIPTOR  (DPE_CERT_LABEL_RANGE_BASE - 3)
#define DPE_CERT_LABEL_AUTHORITY_HASH            (DPE_CERT_LABEL_RANGE_BASE - 4)
#define DPE_CERT_LABEL_AUTHORITY_DESCRIPTOR      (DPE_CERT_LABEL_RANGE_BASE - 5)
#define DPE_CERT_LABEL_MODE                      (DPE_CERT_LABEL_RANGE_BASE - 6)
#define DPE_CERT_LABEL_SUBJECT_PUBLIC_KEY        (DPE_CERT_LABEL_RANGE_BASE - 7)
#define DPE_CERT_LABEL_KEY_USAGE                 (DPE_CERT_LABEL_RANGE_BASE - 8)

/* Below labels are custom and not specified in DICE profile */
#define DPE_CERT_LABEL_SW_COMPONENTS             (DPE_CERT_LABEL_RANGE_BASE - 9)
#define DPE_CERT_LABEL_EXTERNAL_LABEL            (DPE_CERT_LABEL_RANGE_BASE - 10)
#define DPE_CERT_LABEL_CDI_EXPORT                (DPE_CERT_LABEL_RANGE_BASE - 11)
#define DPE_LABEL_CDI_ATTEST                     (1)
#define DPE_LABEL_CDI_SEAL                       (2)
#define DPE_LABEL_CERT_CHAIN                     (3)
#define DPE_LABEL_CERT                           (4)

/* Key usage constant per RFC 5280 */
#define DPE_CERT_KEY_USAGE_CERT_SIGN             (1 << 5);

#ifdef __cplusplus
}
#endif

#endif /* __DPE_CERTIFICATE_COMMON_H__ */
