/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __DPE_BOOT_DATA_H__
#define __DPE_BOOT_DATA_H__

#include "dice_protection_environment.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Get the DPE boot data from the shared area. Must be called before
 *        other functions.
 *
 * \return Returns error code of type dpe_error_t
 */
dpe_error_t initialise_boot_data(void);

/**
 * \brief Derive the initial DPE contexts from the measurements in the boot data
 *        area.
 *
 * \param[in]  rot_ctx_handle    Handle for the RoT context.
 * \param[out] child_ctx_handle  New handle for child context.
 *
 * \return Returns error code of type dpe_error_t
 */
dpe_error_t derive_boot_data_contexts(int rot_ctx_handle,
                                      int *child_ctx_handle);

#ifdef __cplusplus
}
#endif

#endif /* __DPE_BOOT_DATA_H__ */
