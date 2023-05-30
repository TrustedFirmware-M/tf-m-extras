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
 * \brief Log the derive child command parameters.
 */
void log_derive_child(int context_handle,
                      bool retain_parent_context,
                      bool allow_child_to_derive,
                      bool create_certificate,
                      const DiceInputValues *dice_inputs);

/**
 * \brief Log the certify key command parameters.
 */
void log_certify_key(int context_handle,
                     bool retain_context,
                     const uint8_t *public_key,
                     size_t public_key_size,
                     const uint8_t *label,
                     size_t label_size);

#else /* TFM_PARTITION_LOG_LEVEL */

#define log_derive_child(...)
#define log_certify_key(...)

#endif /* TFM_PARTITION_LOG_LEVEL */

#ifdef __cplusplus
}
#endif

#endif /* __DPE_LOG_H__ */
