/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __TFM_DELEGATED_ATTEST_DEFS_H__
#define __TFM_DELEGATED_ATTEST_DEFS_H__

#ifdef __cplusplus
extern "C" {
#endif

/* TF-M Delegated Attestation message types that distinguish its services. */
#define DELEGATED_ATTEST_GET_DELEGATED_KEY      1001U
#define DELEGATED_ATTEST_GET_PLATFORM_TOKEN     1002U

#ifdef __cplusplus
}
#endif

#endif /* __TFM_DELEGATED_ATTEST_DEFS_H__ */
