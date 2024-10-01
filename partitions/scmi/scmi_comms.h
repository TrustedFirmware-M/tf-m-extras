/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 */

#ifndef __SCMI_COMMS_H__
#define __SCMI_COMMS_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SCMI_COMMS_SUCCESS = 0,
    SCMI_COMMS_GENERIC_ERROR,
    SCMI_COMMS_INVALID_ARGUMENT,
    SCMI_COMMS_HARDWARE_ERROR,
} scmi_comms_err_t;

#ifdef __cplusplus
}
#endif

#endif /* __SCMI_COMMS_H__ */
