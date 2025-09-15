/*
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdint.h>
#include <stdbool.h>
#include "psa/error.h"
#include "psa/service.h"
#include "psa_manifest/pid.h"
#include "psa_manifest/tfm_adac.h"

#include "target_cfg.h"
#include "tfm_plat_otp.h"
#include "tfm_peripherals_def.h"
#include "psa_adac_platform.h"

#include "tfm_log.h"

#define ROTPK_SIZE 32

static uint8_t secure_debug_rotpk[ROTPK_SIZE];

static bool read_persistent_debug_state(void)
{
    //TODO: implement persistent storage of debug state
    return false;
}

psa_status_t adac_sp_init(bool *is_service_enabled)
{
    enum tfm_plat_err_t err;
    enum plat_otp_lcs_t lcs;

    *is_service_enabled = false;

    /* Read LCS from OTP */
    err = tfm_plat_otp_read(PLAT_OTP_ID_LCS, sizeof(lcs), (uint8_t*)&lcs);
    if (err != TFM_PLAT_ERR_SUCCESS) {
        ERROR_RAW("ADAC: Failed to read LCS \n");
        return PSA_ERROR_SERVICE_FAILURE;
    }

    if (lcs != PLAT_OTP_LCS_SECURED) {
        /* Device is not in secured state, hence ADAC service should be
         * disabled
         */

    } else {
        err = tfm_plat_otp_read(SECURE_DEBUG_ROTPK_ID, ROTPK_SIZE,
                                secure_debug_rotpk);
        if (err != TFM_PLAT_ERR_SUCCESS) {
            ERROR_RAW("ADAC: Failed to secure debug key \n");
            return PSA_ERROR_SERVICE_FAILURE;
        }

        *is_service_enabled = true;
    }

    return PSA_SUCCESS;
}

/**
 * \brief The ADAC partition's entry function.
 */
psa_status_t tfm_adac_init(void)
{
    psa_status_t status;
    int rc;
    bool is_session_in_progress, is_service_enabled;

    status = adac_sp_init(&is_service_enabled);
    INFO("ADAC partition initialised\n");
    if (status == PSA_SUCCESS && is_service_enabled) {

        psa_adac_platform_init();
        psa_irq_enable(ADAC_REQUEST_SIGNAL);
        while(1) {

            /* First wait for Interrupt */
            (void)psa_wait(ADAC_REQUEST_SIGNAL, PSA_BLOCK);

            is_session_in_progress = read_persistent_debug_state();
            if (is_session_in_progress) {
                ERROR_RAW("ADAC: Debug session already in progress\n");
                psa_eoi(ADAC_REQUEST_SIGNAL);
                continue;
            }

            /* Authenticate incoming debug request */
            rc = tfm_to_psa_adac_platform_secure_debug(secure_debug_rotpk, ROTPK_SIZE);
            if (rc != 0) {
                /* Authentication failure */
                ERROR_RAW("ADAC: Service request failed\n");
                return PSA_ERROR_NOT_PERMITTED;
            }
            psa_eoi(ADAC_REQUEST_SIGNAL);
        }
    }

    return PSA_SUCCESS;
}
