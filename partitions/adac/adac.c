/*
 * Copyright (c) 2022-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdint.h>
#include <stdbool.h>
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
static uint32_t current_debug_session;

static uint32_t read_persistent_debug_state(void)
{
    uint16_t read_mask;
    uint32_t reg_value;
    uint32_t debug_state;

    struct rss_sysctrl_t *sysctrl = (struct rss_sysctrl_t *)RSS_SYSCTRL_BASE_S;
    reg_value = sysctrl->reset_syndrome;

    /* Bits 24:31 (SWSYN) are allocated for software defined reset syndrome */
    reg_value = (reg_value >> 24) & 0xFF;
    /* Use last TFM_PLAT_LAST_CCA_ADAC_ZONE number of bits of
     * RESET_SYNDROME.SWSYN register for conveying debug state information
     */
    read_mask = (1 << TFM_PLAT_LAST_CCA_ADAC_ZONE) - 1;
    debug_state = reg_value & read_mask;

    return debug_state;
}

static void write_persistent_debug_state(uint32_t debug_state)
{
    struct rss_sysctrl_t *sysctrl = (struct rss_sysctrl_t *)RSS_SYSCTRL_BASE_S;
    uint32_t reg_value = sysctrl->swreset;

    /* Clear bits 24:31 (SWSYN)in SWRESET reg */
    reg_value = reg_value & 0x00FFFFFF;
    sysctrl->swreset = reg_value | ((debug_state & 0xFF) << 24);
}

static psa_status_t set_non_cca_debug(uint32_t debug_request)
{
//    TODO: Implement the required updates
    current_debug_session = debug_request;

    return PSA_SUCCESS;
}

static psa_status_t set_cca_debug(uint32_t debug_request)
{
    enum tfm_platform_err_t plat_err;

    write_persistent_debug_state(debug_request);

    /* Trigger a reset */
    plat_err = tfm_platform_system_reset();
    if (plat_err != TFM_PLATFORM_ERR_SUCCESS) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return PSA_SUCCESS;
}

psa_status_t adac_service_request(uint32_t debug_request)
{
    int rc;

    /* check if invalid debug request */
    if (debug_request & ~((1U << (TFM_PLAT_MAX_NUM_DEBUG_ZONES - 1)) - 1)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (debug_request == current_debug_session) {
        /* Do nothing as requested session already in progress */
        return PSA_SUCCESS;
    }

    if ((current_debug_session != TFM_PLAT_NO_DEBUG) &&
        (debug_request != TFM_PLAT_NO_DEBUG)) {

        /* A debug session is already in progress; terminate it first before
         * any new request
         */
        return PSA_ERROR_NOT_PERMITTED;
    }

    if (debug_request == TFM_PLAT_NO_DEBUG) {
        /* Request to terminate the current debug session in progress */
        if (current_debug_session & ((1 << TFM_PLAT_LAST_CCA_ADAC_ZONE) - 1)) {
            return set_cca_debug(TFM_PLAT_NO_DEBUG);
        } else {
            return set_non_cca_debug(TFM_PLAT_NO_DEBUG);
        }
    }

    /* Authenticate incoming debug request */
    rc = tfm_to_psa_adac_rss_secure_debug(secure_debug_rotpk, ROTPK_SIZE);
    if (rc != 0) {
        /* Authentication failure */
        return PSA_ERROR_NOT_PERMITTED;
    }

    if (debug_request & ((1 << TFM_PLAT_LAST_CCA_ADAC_ZONE) - 1)) {
        return set_cca_debug(debug_request);
    } else {
        return set_non_cca_debug(debug_request);
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

    if(lcs != PLAT_OTP_LCS_SECURED) {
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
        /* Read current value of debug state from PSI */
        current_debug_session = read_persistent_debug_state();
    }

    return PSA_SUCCESS;
}
