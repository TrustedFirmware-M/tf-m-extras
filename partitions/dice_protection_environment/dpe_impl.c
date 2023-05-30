/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dpe_impl.h"

#include <string.h>

#include "dpe_log.h"

dpe_error_t dpe_derive_child_impl(int context_handle,
                                  bool retain_parent_context,
                                  bool allow_child_to_derive,
                                  bool create_certificate,
                                  const DiceInputValues *dice_inputs,
                                  int *child_context_handle,
                                  int *new_context_handle)
{
    log_derive_child(context_handle, retain_parent_context,
                     allow_child_to_derive, create_certificate, dice_inputs);

    *child_context_handle = 123;
    *new_context_handle = 456;

    return DPE_NO_ERROR;
}

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
                                 int *new_context_handle)
{
    log_certify_key(context_handle, retain_context, public_key, public_key_size,
                    label, label_size);

    memcpy(certificate_chain_buf, "abc", 4);
    *certificate_chain_actual_size = 4;
    memcpy(derived_public_key_buf, "def", 4);
    *derived_public_key_actual_size = 4;
    *new_context_handle = 789;

    return DPE_NO_ERROR;
}
