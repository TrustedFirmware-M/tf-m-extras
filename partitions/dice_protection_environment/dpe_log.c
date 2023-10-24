/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dpe_log.h"
#include "dpe_context_mngr.h"

#if (TFM_PARTITION_LOG_LEVEL >= TFM_PARTITION_LOG_LEVEL_DEBUG)

static void print_byte_array(const uint8_t *array, size_t len)
{
    size_t i;

    if (array != NULL) {
        for (i = 0; i < len; ++i) {
            if ((i & 0xF) == 0) {
                LOG_DBGFMT("\r\n   ");
            }
            if (array[i] < 0x10) {
                LOG_DBGFMT(" 0%x", array[i]);
            } else {
                LOG_DBGFMT(" %x", array[i]);
            }
        }
    }

    LOG_DBGFMT("\r\n");
}

static void log_dice_inputs(const DiceInputValues *input)
{
    LOG_DBGFMT(" - DICE code_hash =");
    print_byte_array(input->code_hash, sizeof(input->code_hash));
    LOG_DBGFMT(" - DICE code_descriptor =");
    print_byte_array(input->code_descriptor, input->code_descriptor_size);
    LOG_DBGFMT(" - DICE config_type = %d\r\n", input->config_type);
    LOG_DBGFMT(" - DICE config_value =");
    print_byte_array(input->config_value, sizeof(input->config_value));
    LOG_DBGFMT(" - DICE config_descriptor =");
    print_byte_array(input->config_descriptor, input->config_descriptor_size);
    LOG_DBGFMT(" - DICE authority_hash =");
    print_byte_array(input->authority_hash, sizeof(input->authority_hash));
    LOG_DBGFMT(" - DICE authority_descriptor =");
    print_byte_array(input->authority_descriptor,
                     input->authority_descriptor_size);
    LOG_DBGFMT(" - DICE mode = %d\r\n", input->mode);
    LOG_DBGFMT(" - DICE hidden =");
    print_byte_array(input->hidden, sizeof(input->hidden));
}

void log_derive_rot_context(const DiceInputValues *dice_inputs)
{
    LOG_DBGFMT("DPE DeriveRoTContext:\r\n");
    log_dice_inputs(dice_inputs);
}

void log_derive_context(int context_handle,
                        bool retain_parent_context,
                        bool allow_new_context_to_derive,
                        bool create_certificate,
                        const DiceInputValues *dice_inputs,
                        int32_t client_id)
{
    LOG_DBGFMT("DPE DeriveContext:\r\n");
    LOG_DBGFMT(" - context_handle index = %d\r\n", GET_IDX(context_handle));
    LOG_DBGFMT(" - context_handle nonce = %d\r\n", GET_NONCE(context_handle));
    LOG_DBGFMT(" - retain_parent_context = %d\r\n", retain_parent_context);
    LOG_DBGFMT(" - allow_new_context_to_derive = %d\r\n", allow_new_context_to_derive);
    LOG_DBGFMT(" - create_certificate = %d\r\n", create_certificate);
    log_dice_inputs(dice_inputs);
    LOG_DBGFMT(" - client_id = %d\r\n", client_id);
}

void log_destroy_context(int context_handle, bool destroy_recursively)
{
    LOG_DBGFMT("DPE DestroyContext:\r\n");
    LOG_DBGFMT(" - context_handle index = %d\r\n", GET_IDX(context_handle));
    LOG_DBGFMT(" - context_handle nonce = %d\r\n", GET_NONCE(context_handle));
    LOG_DBGFMT(" - destroy_recursively = %d\r\n", destroy_recursively);
}

void log_certify_key(int context_handle,
                     bool retain_context,
                     const uint8_t *public_key,
                     size_t public_key_size,
                     const uint8_t *label,
                     size_t label_size)
{
    LOG_DBGFMT("DPE CertifyKey:\r\n");
    LOG_DBGFMT(" - context_handle index = %d\r\n", GET_IDX(context_handle));
    LOG_DBGFMT(" - context_handle nonce = %d\r\n", GET_NONCE(context_handle));
    LOG_DBGFMT(" - retain_context = %d\r\n", retain_context);
    LOG_DBGFMT(" - public_key =");
    print_byte_array(public_key, public_key_size);
    LOG_DBGFMT(" - label =");
    print_byte_array(label, label_size);
}

void log_intermediate_certificate(uint16_t layer_idx,
                                  const uint8_t *cert_buf,
                                  size_t cert_buf_size)
{
    LOG_DBGFMT("DPE Intermediate Certificate:\r\n");
    LOG_DBGFMT(" - layer index = %d\r\n", layer_idx);
    LOG_DBGFMT(" - certificate =");
    print_byte_array(cert_buf, cert_buf_size);
}

void log_certificate_chain(const uint8_t *certificate_chain_buf,
                           size_t certificate_chain_size)
{
    LOG_DBGFMT("DPE Certificate Chain:\r\n");
    LOG_DBGFMT(" - size = %d\r\n", certificate_chain_size);
    print_byte_array(certificate_chain_buf, certificate_chain_size);
}

#endif /* TFM_PARTITION_LOG_LEVEL */
