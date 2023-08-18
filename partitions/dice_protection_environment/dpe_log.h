/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __DPE_LOG_H__
#define __DPE_LOG_H__

#include "dice_protection_environment.h"
#include "tfm_sp_log.h"

#ifdef __cplusplus
extern "C" {
#endif

#if (TFM_PARTITION_LOG_LEVEL >= TFM_PARTITION_LOG_LEVEL_DEBUG)

/**
 * \brief Log the derive rot context command parameters.
 */
void log_derive_rot_context(const DiceInputValues *dice_inputs);

/**
 * \brief Log the derive child command parameters.
 */
void log_derive_child(int context_handle,
                      bool retain_parent_context,
                      bool allow_child_to_derive,
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
 * \brief Log intermediate layer certificate contents.
 */
void log_intermediate_certificate(uint16_t layer_idx,
                                  const uint8_t *cert_buf,
                                  size_t cert_buf_size);

/**
 * \brief Log Certificate chain contents.
 */
void log_certificate_chain(const uint8_t *certificate_chain_buf,
                           size_t certificate_chain_size);

#else /* TFM_PARTITION_LOG_LEVEL */

#define log_derive_rot_context(...)
#define log_derive_child(...)
#define log_destroy_context(...)
#define log_certify_key(...)
#define log_intermediate_certificate(...)
#define log_certificate_chain(...)

#endif /* TFM_PARTITION_LOG_LEVEL */

#ifdef __cplusplus
}
#endif

#endif /* __DPE_LOG_H__ */
