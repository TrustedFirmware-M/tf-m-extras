/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __DPE_IMPL_H__
#define __DPE_IMPL_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dice_protection_environment.h"
#include "ext/dice/dice.h"
#include "psa/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The maximum supported public key size is for a 384-bit ECC curve */
#define DPE_PUBLIC_KEY_MAX_SIZE PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(384)

/* The maximum certificate chain size that can be output by this
 * implementation
 */
#define DPE_CERTIFICATE_CHAIN_MAX_SIZE 2048

/* Internal DPE service implementation of dpe_certify_key() */
dpe_error_t dpe_certify_key_impl(int context_handle,
                                 bool retain_context,
                                 const uint8_t *public_key,
                                 size_t public_key_size,
                                 const uint8_t *label,
                                 size_t label_size,
                                 uint8_t *certificate_chain_buf,
                                 size_t certificate_chain_buf_size,
                                 size_t *certificate_chain_actual_size,
                                 uint8_t *derived_public_key_buf,
                                 size_t derived_public_key_buf_size,
                                 size_t *derived_public_key_actual_size,
                                 int *new_context_handle);

#ifdef __cplusplus
}
#endif

#endif /* __DPE_IMPL_H__ */
