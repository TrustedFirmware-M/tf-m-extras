/*
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __DPE_LOG_H__
#define __DPE_LOG_H__

#include "dice_protection_environment.h"
#include "dpe_context_mngr.h"
#include "tfm_log_unpriv.h"

#ifdef __cplusplus
extern "C" {
#endif

#if (LOG_LEVEL_UNPRIV >= LOG_LEVEL_VERBOSE)

/**
 * \brief Log the derive rot context command parameters.
 */
void log_derive_rot_context(const DiceInputValues *dice_inputs);

/**
 * \brief Log the derive context command parameters.
 */
void log_derive_context(int context_handle,
                        uint32_t cert_id,
                        bool retain_parent_context,
                        bool allow_new_context_to_derive,
                        bool create_certificate,
                        const DiceInputValues *dice_inputs,
                        int32_t client_id);

/**
 * \brief Log the destroy context command parameters.
 */
void log_destroy_context(int context_handle,
                         bool destroy_recursively);

/**
 * \brief Log the certify key command parameters.
 */
void log_certify_key(int context_handle,
                     bool retain_context,
                     const uint8_t *public_key,
                     size_t public_key_size,
                     const uint8_t *label,
                     size_t label_size);

/**
 * \brief Log the get certificate chain command parameters.
 */
void log_get_certificate_chain(int context_handle,
                               bool retain_context,
                               bool clear_from_context,
                               size_t cert_chain_buf_size);

/**
 * \brief Log intermediate certificate contents.
 */
void log_intermediate_certificate(const uint8_t *cert_buf,
                                  size_t cert_buf_size);

/**
 * \brief Log Certificate chain contents.
 */
void log_certificate_chain(const uint8_t *certificate_chain_buf,
                           size_t certificate_chain_size);

/**
 * \brief Log derive context output handles.
 */
void log_derive_context_output_handles(int parent_context_handle,
                                       int new_context_handle);

/**
 * \brief Log certify key output handle.
 */
void log_certify_key_output_handle(int new_context_handle);

/**
 * \brief Log get certificate chain output handle.
 */
void log_get_certificate_chain_output_handle(int new_context_handle);

/**
 * \brief Log component context metadata.
 */
void log_dpe_component_ctx_metadata(const struct component_context_t *ctx_ptr,
                                    int component_idx);

/**
 * \brief Log certificate context metadata.
 */
void log_dpe_cert_ctx_metadata(const struct cert_context_t *ctx_ptr);

/**
 * \brief Log the derive context output.
 */
void log_derive_context_output(int *new_context_handle,
                               int *new_parent_context_handle,
                               struct component_context_t *derived_ctx,
                               int free_component_idx,
                               struct cert_context_t *cert_ctx,
                               uint8_t *new_certificate_buf,
                               size_t *new_certificate_actual_size);

#else /* LOG_LEVEL_UNPRIV */

#define log_derive_rot_context(...)
#define log_derive_context(...)
#define log_destroy_context(...)
#define log_certify_key(...)
#define log_get_certificate_chain(...)
#define log_intermediate_certificate(...)
#define log_certificate_chain(...)
#define log_derive_context_output_handles(...)
#define log_certify_key_output_handle(...)
#define log_get_certificate_chain_output_handle(...)
#define log_dpe_component_ctx_metadata(...)
#define log_dpe_cert_ctx_metadata(...)
#define log_derive_context_output(...)

#endif /* LOG_LEVEL_UNPRIV */

#ifdef __cplusplus
}
#endif

#endif /* __DPE_LOG_H__ */
