/*
 * Copyright (c) 2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __DPE_CMD_ENCODE_H__
#define __DPE_CMD_ENCODE_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct derive_context_input_t {
    int context_handle;
    uint32_t cert_id;
    bool retain_parent_context;
    bool allow_new_context_to_derive;
    bool create_certificate;
    const DiceInputValues *dice_inputs;
    int32_t target_locality;
    bool return_certificate;
    bool allow_new_context_to_export;
    bool export_cdi;
};

struct derive_context_output_t {
    int new_context_handle;
    int new_parent_context_handle;
    const uint8_t *new_certificate;
    size_t new_certificate_size;
    const uint8_t *exported_cdi;
    size_t exported_cdi_size;
};

struct destroy_context_input_t {
    int context_handle;
    bool destroy_recursively;
};

struct certify_key_input_t {
    int context_handle;
    bool retain_context;
    const uint8_t *public_key;
    size_t public_key_size;
    const uint8_t *label;
    size_t label_size;
};

struct certify_key_output_t {
    const uint8_t *certificate_chain;
    size_t certificate_chain_size;
    const uint8_t *derived_public_key;
    size_t derived_public_key_size;
    int new_context_handle;
};

struct get_certificate_chain_input_t {
    int context_handle;
    bool retain_context;
    bool clear_from_context;
};

struct get_certificate_chain_output_t {
    const uint8_t *certificate_chain;
    size_t certificate_chain_size;
    int new_context_handle;
};

#ifdef __cplusplus
}
#endif

#endif /* __DPE_CMD_ENCODE_H__ */
