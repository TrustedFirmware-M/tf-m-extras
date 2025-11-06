/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 */

#ifndef __SCMI_HAL_H__
#define __SCMI_HAL_H__

#include "scmi_comms.h"

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    /** No special flags for initialization sequence */
    SCMI_INIT_SEQ_FLAG_NONE = 0,

    /** Initialization sequence requires IRQ enable */
    SCMI_INIT_SEQ_FLAG_IRQ_EN = (UINT32_C(0x1) << 1),
    /** Initialization sequence requires IRQ waiting */
    SCMI_INIT_SEQ_FLAG_IRQ_WAIT = (UINT32_C(0x1) << 2),
    /** Initialization sequence requires SYSTEM_POWER_STATE_NOTIFY with wait */
    SCMI_INIT_SEQ_FLAG_SUBSCRIBE_WAIT = (UINT32_C(0x1) << 3),

    _SCMI_INIT_SEQ_FLAG_IRQ_MAX = UINT32_MAX
} scmi_init_sequence_flags_t;

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
 * \brief Check the platform-specific properties via a set of flags.
 *
 * \return SCMI_COMMS_SUCCESS on success, error otherwise.
 */
scmi_comms_err_t scmi_hal_init_sequence_flags(
    scmi_init_sequence_flags_t *init_flags);

/**
 * \brief Hook a platform-specific initial sequencing point with the SCMI
 *        platform.
 *
 * \param[out] hook_done  A condition that the sequence hook has completed
 *
 * \return SCMI_COMMS_SUCCESS on success, error otherwise.
 */
scmi_comms_err_t scmi_hal_init_sequence_hook(bool *hook_done);

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
