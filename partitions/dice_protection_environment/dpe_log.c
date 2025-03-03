/*
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dpe_log.h"
#include "dpe_context_mngr.h"

#if (LOG_LEVEL_UNPRIV >= LOG_LEVEL_VERBOSE)
#define LOG_BOOL_VAL(arg)   ((arg) ? "true" : "false")

static void print_byte_array(const uint8_t *array, size_t len)
{
    size_t i;

    if (array != NULL) {
        for (i = 0; i < len; ++i) {
            if ((i & 0xF) == 0) {
                VERBOSE_UNPRIV_RAW("\n   ");
            }
            if (array[i] < 0x10) {
                VERBOSE_UNPRIV_RAW(" 0%x", array[i]);
            } else {
                VERBOSE_UNPRIV_RAW(" %x", array[i]);
            }
        }
    }

    VERBOSE_UNPRIV_RAW("\n");
}

static void log_dice_inputs(const DiceInputValues *input)
{
    VERBOSE_UNPRIV_RAW(" - DICE code_hash =");
    print_byte_array(input->code_hash, sizeof(input->code_hash));
    VERBOSE_UNPRIV_RAW(" - DICE code_descriptor =");
    print_byte_array(input->code_descriptor, input->code_descriptor_size);
    VERBOSE_UNPRIV_RAW(" - DICE config_type = %d\n", input->config_type);
    VERBOSE_UNPRIV_RAW(" - DICE config_value =");
    print_byte_array(input->config_value, sizeof(input->config_value));
    VERBOSE_UNPRIV_RAW(" - DICE config_descriptor =");
    print_byte_array(input->config_descriptor, input->config_descriptor_size);
    VERBOSE_UNPRIV_RAW(" - DICE authority_hash =");
    print_byte_array(input->authority_hash, sizeof(input->authority_hash));
    VERBOSE_UNPRIV_RAW(" - DICE authority_descriptor =");
    print_byte_array(input->authority_descriptor,
                     input->authority_descriptor_size);
    VERBOSE_UNPRIV_RAW(" - DICE mode = %d\n", input->mode);
    VERBOSE_UNPRIV_RAW(" - DICE hidden =");
    print_byte_array(input->hidden, sizeof(input->hidden));
}

void log_derive_rot_context(const DiceInputValues *dice_inputs)
{
    VERBOSE_UNPRIV_RAW("DPE DeriveRoTContext:\n");
    log_dice_inputs(dice_inputs);
}

static void log_handle(int context_handle)
{
    VERBOSE_UNPRIV_RAW(" index - %d,", GET_IDX(context_handle));
    VERBOSE_UNPRIV_RAW(" nonce - 0x%x\n", GET_NONCE(context_handle));
}

void log_derive_context(int context_handle,
                        uint32_t cert_id,
                        bool retain_parent_context,
                        bool allow_new_context_to_derive,
                        bool create_certificate,
                        const DiceInputValues *dice_inputs,
                        int32_t client_id)
{
    VERBOSE_UNPRIV_RAW("DPE DeriveContext:\n");
    VERBOSE_UNPRIV_RAW(" - input context handle:");
    log_handle(context_handle);
    VERBOSE_UNPRIV_RAW(" - cert_id = 0x%x\n", cert_id);
    VERBOSE_UNPRIV_RAW(" - retain_parent_context = %s\n", LOG_BOOL_VAL(retain_parent_context));
    VERBOSE_UNPRIV_RAW(" - allow_new_context_to_derive = %s\n", LOG_BOOL_VAL(allow_new_context_to_derive));
    VERBOSE_UNPRIV_RAW(" - create_certificate = %s\n", LOG_BOOL_VAL(create_certificate));
    log_dice_inputs(dice_inputs);
    VERBOSE_UNPRIV_RAW(" - client_id = %d\n", client_id);
}

void log_destroy_context(int context_handle, bool destroy_recursively)
{
    VERBOSE_UNPRIV_RAW("DPE DestroyContext:\n");
    VERBOSE_UNPRIV_RAW(" - input context handle:");
    log_handle(context_handle);
    VERBOSE_UNPRIV_RAW(" - destroy_recursively = %s\n", LOG_BOOL_VAL(destroy_recursively));
}

void log_certify_key(int context_handle,
                     bool retain_context,
                     const uint8_t *public_key,
                     size_t public_key_size,
                     const uint8_t *label,
                     size_t label_size)
{
    VERBOSE_UNPRIV_RAW("DPE CertifyKey:\n");
    VERBOSE_UNPRIV_RAW(" - input context handle:");
    log_handle(context_handle);
    VERBOSE_UNPRIV_RAW(" - retain_context = %s\n", LOG_BOOL_VAL(retain_context));
    VERBOSE_UNPRIV_RAW(" - public_key =");
    print_byte_array(public_key, public_key_size);
    VERBOSE_UNPRIV_RAW(" - label =");
    print_byte_array(label, label_size);
}

void log_get_certificate_chain(int context_handle,
                               bool retain_context,
                               bool clear_from_context,
                               size_t cert_chain_buf_size)
{
    VERBOSE_UNPRIV_RAW("DPE GetCertificateChain:\n");
    VERBOSE_UNPRIV_RAW(" - input context handle:");
    log_handle(context_handle);
    VERBOSE_UNPRIV_RAW(" - retain_context = %s\n", LOG_BOOL_VAL(retain_context));
    VERBOSE_UNPRIV_RAW(" - clear_from_context = %s\n", LOG_BOOL_VAL(clear_from_context));
    VERBOSE_UNPRIV_RAW(" - cert_chain_buf_size = %d\n", cert_chain_buf_size);
}

void log_intermediate_certificate(const uint8_t *cert_buf,
                                  size_t cert_size)
{
    VERBOSE_UNPRIV_RAW("DPE Intermediate Certificate:\n");
    VERBOSE_UNPRIV_RAW(" - size = %d\n", cert_size);
    VERBOSE_UNPRIV_RAW(" - certificate =");
    print_byte_array(cert_buf, cert_size);
}

void log_certificate_chain(const uint8_t *certificate_chain_buf,
                           size_t certificate_chain_size)
{
    VERBOSE_UNPRIV_RAW("DPE Certificate Chain:\n");
    VERBOSE_UNPRIV_RAW(" - size = %d\n", certificate_chain_size);
    print_byte_array(certificate_chain_buf, certificate_chain_size);
}

void log_derive_context_output_handles(int parent_context_handle,
                                       int new_context_handle)
{
    VERBOSE_UNPRIV_RAW("DPE DeriveContext output handles:\n");
    VERBOSE_UNPRIV_RAW(" - parent context handle:");
    log_handle(parent_context_handle);
    VERBOSE_UNPRIV_RAW(" - new context handle:");
    log_handle(new_context_handle);
}

void log_certify_key_output_handle(int new_context_handle)
{
    VERBOSE_UNPRIV_RAW("DPE CertifyKey output handle:\n");
    VERBOSE_UNPRIV_RAW(" - new context handle:");
    log_handle(new_context_handle);
}

void log_get_certificate_chain_output_handle(int new_context_handle)
{
    VERBOSE_UNPRIV_RAW("DPE GetCertificateChain output handle:\n");
    VERBOSE_UNPRIV_RAW(" - new context handle:");
    log_handle(new_context_handle);
}

void log_dpe_component_ctx_metadata(const struct component_context_t *ctx_ptr,
                                    int component_index)
{
    VERBOSE_UNPRIV_RAW(" DPE component_ctx_array[%d]: \n", component_index);
    VERBOSE_UNPRIV_RAW("  - in_use = %s\n", LOG_BOOL_VAL(ctx_ptr->in_use));
    VERBOSE_UNPRIV_RAW("  - is_allowed_to_derive = %s\n",
                LOG_BOOL_VAL(ctx_ptr->is_allowed_to_derive));
    VERBOSE_UNPRIV_RAW("  - is_export_cdi_allowed = %s\n",
                LOG_BOOL_VAL(ctx_ptr->is_export_cdi_allowed));
    VERBOSE_UNPRIV_RAW("  - nonce = 0x%x\n", ctx_ptr->nonce);
    VERBOSE_UNPRIV_RAW("  - target_locality = %d\n", ctx_ptr->target_locality);
    VERBOSE_UNPRIV_RAW("  - expected_mhu_id = %u\n", ctx_ptr->expected_mhu_id);
    VERBOSE_UNPRIV_RAW("  - parent_comp_ctx->nonce = %d\n", ctx_ptr->parent_comp_ctx->nonce);
    if (ctx_ptr->linked_cert_ctx != NULL) {
        VERBOSE_UNPRIV_RAW("  - linked_cert_ctx->cert_id = %d\n",
                   ctx_ptr->linked_cert_ctx->cert_id);
    }
}

void log_dpe_cert_ctx_metadata(const struct cert_context_t *ctx_ptr)
{
    VERBOSE_UNPRIV_RAW(" DPE cert_ctx_array[]: \n");
    VERBOSE_UNPRIV_RAW("  - cert_id = 0x%x\n", ctx_ptr->cert_id);
    VERBOSE_UNPRIV_RAW("  - state = %d\n", ctx_ptr->state);
    VERBOSE_UNPRIV_RAW("  - is_external_pub_key_provided = %s\n",
                LOG_BOOL_VAL(ctx_ptr->is_external_pub_key_provided));
    VERBOSE_UNPRIV_RAW("  - is_cdi_to_be_exported = %s\n",
                LOG_BOOL_VAL(ctx_ptr->is_cdi_to_be_exported));
}

void log_derive_context_output(int *new_context_handle,
                               int *new_parent_context_handle,
                               struct component_context_t *derived_ctx,
                               int free_component_idx,
                               struct cert_context_t *cert_ctx,
                               uint8_t *new_certificate_buf,
                               size_t *new_certificate_actual_size)
{
    log_derive_context_output_handles(*new_parent_context_handle,
                                      *new_context_handle);

    /* Log component context, certificate context & certificate if no error */
    log_dpe_component_ctx_metadata(derived_ctx, free_component_idx);
    if (cert_ctx != NULL) {
        log_dpe_cert_ctx_metadata(cert_ctx);
    }
    if (new_certificate_actual_size != NULL && *new_certificate_actual_size > 0) {
        log_intermediate_certificate(new_certificate_buf,
                                     *new_certificate_actual_size);
    }
}

#endif /* LOG_LEVEL_UNPRIV */
