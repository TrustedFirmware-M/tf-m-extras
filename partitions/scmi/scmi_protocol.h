/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 */

#ifndef __SCMI_PROTOCOL_H__
#define __SCMI_PROTOCOL_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SCMI status definitions
 */
#define SCMI_STATUS_SUCCESS            INT32_C(0)
#define SCMI_STATUS_NOT_SUPPORTED      INT32_C(-1)
#define SCMI_STATUS_INVALID_PARAMETERS INT32_C(-2)
#define SCMI_STATUS_DENIED             INT32_C(-3)
#define SCMI_STATUS_NOT_FOUND          INT32_C(-4)
#define SCMI_STATUS_OUT_OF_RANGE       INT32_C(-5)
#define SCMI_STATUS_BUSY               INT32_C(-6)
#define SCMI_STATUS_COMMS_ERROR        INT32_C(-7)
#define SCMI_STATUS_GENERIC_ERROR      INT32_C(-8)
#define SCMI_STATUS_HARDWARE_ERROR     INT32_C(-9)
#define SCMI_STATUS_PROTOCOL_ERROR     INT32_C(-10)

/**
 * SCMI message types
 */
#define SCMI_MESSAGE_TYPE_COMMAND      UINT8_C(0)
#define SCMI_MESSAGE_TYPE_NOTIFICATION UINT8_C(3)

/**
 * SCMI protocol IDs
 */
#define SCMI_PROTOCOL_ID_SYS_POWER_STATE UINT8_C(0x12)

/**
 * SCMI message IDs
 */
#define SCMI_MESSAGE_ID_SYS_POWER_STATE_SET      UINT8_C(0x3)
#define SCMI_MESSAGE_ID_SYS_POWER_STATE_NOTIFY   UINT8_C(0x5)
#define SCMI_MESSAGE_ID_SYS_POWER_STATE_NOTIFIER UINT8_C(0x0)

/**
 * SCMI system power state messages
 */
#define SCMI_SYS_POWER_STATE_FLAGS_GRACEFUL_POS 0
#define SCMI_SYS_POWER_STATE_FLAGS_GRACEFUL_MASK \
    (UINT32_C(0x1) << SCMI_SYS_POWER_STATE_FLAGS_GRACEFUL_POS)

#define SCMI_SYS_POWER_STATE_SHUTDOWN   UINT32_C(0)
#define SCMI_SYS_POWER_STATE_COLD_RESET UINT32_C(1)
#define SCMI_SYS_POWER_STATE_WARM_RESET UINT32_C(2)
#define SCMI_SYS_POWER_STATE_POWER_UP   UINT32_C(3)
#define SCMI_SYS_POWER_STATE_SUSPEND    UINT32_C(4)

/**
 * \brief System power state set message payload.
 */
struct scmi_sys_power_state_set_t {
    uint32_t flags;
    uint32_t system_state;
};

/**
 * \brief System power state set response payload.
 */
struct scmi_sys_power_state_set_response_t {
    int32_t status;
};

/**
 * \brief System power state notification subscription message payload.
 */
struct scmi_sys_power_state_notify_t {
    uint32_t notify_enable; /**< Enable scmi_sys_power_state_notifier_t notifications */
};

/**
 * \brief System power state notification subscription response payload.
 */
struct scmi_sys_power_state_notify_response_t {
    int32_t status;
};

/**
 * \brief System power state notification message payload.
 */
struct scmi_sys_power_state_notifier_t {
    uint32_t agent_id; /**< ID of the agent that caused the power state transition */
    uint32_t flags;
    uint32_t system_state;
};

#ifdef __cplusplus
}
#endif

#endif /* __SCMI_PROTOCOL_H__ */
