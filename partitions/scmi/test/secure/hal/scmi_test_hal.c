/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 */

#include "psa/service.h"
#include "psa_manifest/scmi_comms.h"
#include "scmi_hal.h"
#include "scmi_protocol.h"
#include "tfm_hal_platform.h"
#include "tfm_plat_test.h"
#include "cmsis_compiler.h"

#include <stdbool.h>
#include <stdint.h>

char test_shared_mem[SCP_SHARED_MEMORY_SIZE] __ALIGNED(8);
volatile bool test_doorbell_sender;
volatile bool test_doorbell_receiver;

scmi_comms_err_t scmi_hal_shared_memory_init(void)
{
    return SCMI_COMMS_SUCCESS;
}

scmi_comms_err_t scmi_hal_doorbell_init(void)
{
    return SCMI_COMMS_SUCCESS;
}

scmi_comms_err_t scmi_hal_doorbell_ring(void)
{
    /* Set the sender doorbell */
    test_doorbell_sender = true;

    /* Add an extra wait on the doorbell to allow the test partition to run
     * (only required because testing is done locally).
     */
    psa_wait(SCP_DOORBELL_SIGNAL, PSA_BLOCK);
    scmi_hal_doorbell_clear();
    psa_eoi(SCP_DOORBELL_SIGNAL);

    return SCMI_COMMS_SUCCESS;
}

scmi_comms_err_t scmi_hal_doorbell_clear(void)
{
    /* Clear the receiver doorbell */
    test_doorbell_receiver = false;

    /* Stop the timer that was used to trigger the doorbell */
    tfm_plat_test_secure_timer_stop();

    return SCMI_COMMS_SUCCESS;
}
