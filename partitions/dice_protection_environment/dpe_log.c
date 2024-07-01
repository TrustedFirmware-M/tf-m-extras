/*
 * Copyright (c) 2023-2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dpe_log.h"
#include "dpe_context_mngr.h"

#if (TFM_PARTITION_LOG_LEVEL >= TFM_PARTITION_LOG_LEVEL_DEBUG)
#define LOG_BOOL_VAL(arg)   ((arg) ? "true" : "false")

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

static void log_handle(int context_handle)
{
    LOG_DBGFMT(" index - %d,", GET_IDX(context_handle));
    LOG_DBGFMT(" nonce - 0x%x\r\n", GET_NONCE(context_handle));
}

void log_derive_context(int context_handle,
                        uint32_t cert_id,
                        bool retain_parent_context,
                        bool allow_new_context_to_derive,
                        bool create_certificate,
                        const DiceInputValues *dice_inputs,
                        int32_t client_id)
{
    LOG_DBGFMT("DPE DeriveContext:\r\n");
    LOG_DBGFMT(" - input context handle:");
    log_handle(context_handle);
    LOG_DBGFMT(" - cert_id = 0x%x\r\n", cert_id);
    LOG_DBGFMT(" - retain_parent_context = %s\r\n", LOG_BOOL_VAL(retain_parent_context));
    LOG_DBGFMT(" - allow_new_context_to_derive = %s\r\n", LOG_BOOL_VAL(allow_new_context_to_derive));
    LOG_DBGFMT(" - create_certificate = %s\r\n", LOG_BOOL_VAL(create_certificate));
    log_dice_inputs(dice_inputs);
    LOG_DBGFMT(" - client_id = %d\r\n", client_id);
}

void log_destroy_context(int context_handle, bool destroy_recursively)
{
    LOG_DBGFMT("DPE DestroyContext:\r\n");
    LOG_DBGFMT(" - input context handle:");
    log_handle(context_handle);
    LOG_DBGFMT(" - destroy_recursively = %s\r\n", LOG_BOOL_VAL(destroy_recursively));
}

void log_certify_key(int context_handle,
                     bool retain_context,
                     const uint8_t *public_key,
                     size_t public_key_size,
                     const uint8_t *label,
                     size_t label_size)
{
    LOG_DBGFMT("DPE CertifyKey:\r\n");
    LOG_DBGFMT(" - input context handle:");
    log_handle(context_handle);
    LOG_DBGFMT(" - retain_context = %s\r\n", LOG_BOOL_VAL(retain_context));
    LOG_DBGFMT(" - public_key =");
    print_byte_array(public_key, public_key_size);
    LOG_DBGFMT(" - label =");
    print_byte_array(label, label_size);
}

void log_get_certificate_chain(int context_handle,
                               bool retain_context,
                               bool clear_from_context,
                               size_t cert_chain_buf_size)
{
    LOG_DBGFMT("DPE GetCertificateChain:\r\n");
    LOG_DBGFMT(" - input context handle:");
    log_handle(context_handle);
    LOG_DBGFMT(" - retain_context = %s\r\n", LOG_BOOL_VAL(retain_context));
    LOG_DBGFMT(" - clear_from_context = %s\r\n", LOG_BOOL_VAL(clear_from_context));
    LOG_DBGFMT(" - cert_chain_buf_size = %d\r\n", cert_chain_buf_size);
}

void log_intermediate_certificate(uint16_t cert_ctx_idx,
                                  const uint8_t *cert_buf,
                                  size_t cert_size)
{
    LOG_DBGFMT("DPE Intermediate Certificate:\r\n");
    LOG_DBGFMT(" - certificate context index = %d\r\n", cert_ctx_idx);
    LOG_DBGFMT(" - size = %d\r\n", cert_size);
    LOG_DBGFMT(" - certificate =");
    print_byte_array(cert_buf, cert_size);
}

void log_certificate_chain(const uint8_t *certificate_chain_buf,
                           size_t certificate_chain_size)
{
    LOG_DBGFMT("DPE Certificate Chain:\r\n");
    LOG_DBGFMT(" - size = %d\r\n", certificate_chain_size);
    print_byte_array(certificate_chain_buf, certificate_chain_size);
}

void log_derive_context_output_handles(int parent_context_handle,
                                       int new_context_handle)
{
    LOG_DBGFMT("DPE DeriveContext output handles:\r\n");
    LOG_DBGFMT(" - parent context handle:");
    log_handle(parent_context_handle);
    LOG_DBGFMT(" - new context handle:");
    log_handle(new_context_handle);
}

void log_certify_key_output_handle(int new_context_handle)
{
    LOG_DBGFMT("DPE CertifyKey output handle:\r\n");
    LOG_DBGFMT(" - new context handle:");
    log_handle(new_context_handle);
}

void log_get_certificate_chain_output_handle(int new_context_handle)
{
    LOG_DBGFMT("DPE GetCertificateChain output handle:\r\n");
    LOG_DBGFMT(" - new context handle:");
    log_handle(new_context_handle);
}

void log_dpe_component_ctx_metadata(const struct component_context_t *ctx_ptr,
                                    int component_index)
{
    LOG_DBGFMT(" DPE component_ctx_array[%d]: \r\n", component_index);
    LOG_DBGFMT("  - in_use = %s\r\n", LOG_BOOL_VAL(ctx_ptr->in_use));
    LOG_DBGFMT("  - is_allowed_to_derive = %s\r\n",
                LOG_BOOL_VAL(ctx_ptr->is_allowed_to_derive));
    LOG_DBGFMT("  - is_export_cdi_allowed = %s\r\n",
                LOG_BOOL_VAL(ctx_ptr->is_export_cdi_allowed));
    LOG_DBGFMT("  - nonce = 0x%x\r\n", ctx_ptr->nonce);
    LOG_DBGFMT("  - parent_idx = %d\r\n", ctx_ptr->parent_idx);
    LOG_DBGFMT("  - linked_cert_ctx_idx = %d\r\n", ctx_ptr->linked_cert_ctx_idx);
    LOG_DBGFMT("  - target_locality = %d\r\n", ctx_ptr->target_locality);
    LOG_DBGFMT("  - expected_mhu_id = %u\r\n", ctx_ptr->expected_mhu_id);
}

void log_dpe_cert_ctx_metadata(const struct cert_context_t *ctx_ptr,
                               uint16_t cert_ctx_idx)
{
    LOG_DBGFMT(" DPE cert_ctx_array[%d]: \r\n", cert_ctx_idx);
    LOG_DBGFMT("  - cert_id = 0x%x\r\n", ctx_ptr->cert_id);
    LOG_DBGFMT("  - parent_cert_ctx_idx = %d\r\n", ctx_ptr->parent_cert_ctx_idx);
    LOG_DBGFMT("  - state = %d\r\n", ctx_ptr->state);
    LOG_DBGFMT("  - is_external_pub_key_provided = %s\r\n",
                LOG_BOOL_VAL(ctx_ptr->is_external_pub_key_provided));
    LOG_DBGFMT("  - is_cdi_to_be_exported = %s\r\n",
                LOG_BOOL_VAL(ctx_ptr->is_cdi_to_be_exported));
}

#endif /* TFM_PARTITION_LOG_LEVEL */
