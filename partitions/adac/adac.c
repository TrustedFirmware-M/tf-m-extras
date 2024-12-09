/*
 * Copyright (c) 2022-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "tfm_plat_defs.h"
#include "tfm_plat_otp.h"
#include "platform_regs.h"
#include "platform_base_address.h"
#include "tfm_platform_system.h"
#include "psa_adac_platform.h"
#include "target_cfg.h"
#include "tfm_platform_api.h"

#define ROTPK_SIZE 32

static uint8_t secure_debug_rotpk[ROTPK_SIZE];
static bool is_session_in_progress;

static bool read_persistent_debug_state(void)
{
    uint32_t reg_value;
    struct rse_sysctrl_t *sysctrl = (struct rse_sysctrl_t *)RSE_SYSCTRL_BASE_S;

    reg_value = sysctrl->reset_syndrome;

    return (reg_value & (1 << SWSYN_DEBUG_STATE_IN_BOOT_BIT_POS));
}

psa_status_t adac_service_request(uint32_t debug_request)
{
    int rc;
    /* Not relevant anymore. Will be removed once the API gets updated */
    (void) debug_request;

    /* Read current value of debug state from PSI */
    is_session_in_progress = read_persistent_debug_state();

    if (is_session_in_progress) {
        /* Do nothing as a session is already in progress */
        return PSA_ERROR_CONNECTION_BUSY;

    }

    /* Authenticate incoming debug request */
   rc = tfm_to_psa_adac_rse_secure_debug(secure_debug_rotpk, ROTPK_SIZE);
   if (rc != 0) {
       /* Authentication failure */
       return PSA_ERROR_NOT_PERMITTED;
   }

    return PSA_SUCCESS;
}

psa_status_t adac_sp_init(bool *is_service_enabled)
{
    enum tfm_plat_err_t err;
    enum plat_otp_lcs_t lcs;

    *is_service_enabled = false;

    /* Read LCS from OTP */
    err = tfm_plat_otp_read(PLAT_OTP_ID_LCS, sizeof(lcs), (uint8_t*)&lcs);
    if (err != TFM_PLAT_ERR_SUCCESS) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    if (lcs != PLAT_OTP_LCS_SECURED) {
        /* Device is not in secured state, hence ADAC service should be
         * disabled
         */

    } else {
        err = tfm_plat_otp_read(PLAT_OTP_ID_SECURE_DEBUG_PK, ROTPK_SIZE,
                                secure_debug_rotpk);
        if (err != TFM_PLAT_ERR_SUCCESS) {
            return PSA_ERROR_SERVICE_FAILURE;
        }

        *is_service_enabled = true;
    }

    return PSA_SUCCESS;
}
