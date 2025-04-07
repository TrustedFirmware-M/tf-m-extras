/*
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __RUNTIME_PROVISIONING_HAL_H__
#define __RUNTIME_PROVISIONING_HAL_H__

enum runtime_provisioning_error_t {
    RUNTIME_PROVISIONING_SUCCESS = 0,
    RUNTIME_PROVISIONING_INVALID_STATE,
    RUNTIME_PROVISIONING_NO_INTERRUPT,
    RUNTIME_PROVISIONING_GENERIC_ERROR,
};

enum runtime_provisioning_error_t runtime_provisioning_hal_init(void);

enum runtime_provisioning_error_t runtime_provisioning_hal_process_message(void);

#endif /* __RUNTIME_PROVISIONING_HAL_H__ */
