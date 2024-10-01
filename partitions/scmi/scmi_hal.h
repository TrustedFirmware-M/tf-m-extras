/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 */

#ifndef __SCMI_HAL_H__
#define __SCMI_HAL_H__

#include "scmi_comms.h"
#include "scmi_hal_defs.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Initialize the SCMI transport shared memory area.
 *
 * \return SCMI_COMMS_SUCCESS on success, SCMI_COMMS_HARDWARE_ERROR on failure.
 */
scmi_comms_err_t scmi_hal_shared_memory_init(void);

/**
 * \brief Initialize the SCMI transport doorbells.
 *
 * \return SCMI_COMMS_SUCCESS on success, SCMI_COMMS_HARDWARE_ERROR on failure.
 */
scmi_comms_err_t scmi_hal_doorbell_init(void);

/**
 * \brief Ring the SCMI transport sender doorbell.
 *
 * \return SCMI_COMMS_SUCCESS on success, SCMI_COMMS_HARDWARE_ERROR on failure.
 */
scmi_comms_err_t scmi_hal_doorbell_ring(void);

/**
 * \brief Clear the SCMI transport receiver doorbell.
 *
 * \return SCMI_COMMS_SUCCESS on success, SCMI_COMMS_HARDWARE_ERROR on failure.
 */
scmi_comms_err_t scmi_hal_doorbell_clear(void);

/**
 * \brief Handle a system power state change.
 *
 * \param[in] agent_id      Identifier of the agent that caused the power state change
 * \param[in] flags         Power state change flags
 * \param[in] system_state  Power state that is being transitioned to
 *
 * \return SCMI status value.
 */
int32_t scmi_hal_sys_power_state(uint32_t agent_id, uint32_t flags,
                                 uint32_t system_state);

#ifdef __cplusplus
}
#endif

#endif /* __SCMI_HAL_H__ */
