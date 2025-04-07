/*
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "runtime_provisioning_hal.h"
#include "psa/service.h"
#include "psa_manifest/runtime_provisioning.h"
#include "tfm_log.h"

void runtime_provisioning_main(void)
{
    enum runtime_provisioning_error_t err;

    err = runtime_provisioning_hal_init();
    if (err == RUNTIME_PROVISIONING_INVALID_STATE) {
        /* Block forever without enabling interrupt as this partition is not
         * required */
        (void)psa_wait(RUNTIME_PROVISIONING_MESSAGE_SIGNAL, PSA_BLOCK);
    } else if (err != RUNTIME_PROVISIONING_SUCCESS) {
        psa_panic();
    }

    psa_irq_enable(RUNTIME_PROVISIONING_MESSAGE_SIGNAL);

    INFO("Runtime provisioning partition initialised\n");

    while (1) {
        (void)psa_wait(RUNTIME_PROVISIONING_MESSAGE_SIGNAL, PSA_BLOCK);
        err = runtime_provisioning_hal_process_message();
        if (err != RUNTIME_PROVISIONING_SUCCESS) {
            psa_panic();
        }
        psa_eoi(RUNTIME_PROVISIONING_MESSAGE_SIGNAL);
    }
}
