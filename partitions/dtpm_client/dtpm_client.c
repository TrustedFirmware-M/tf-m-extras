/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 */

#include <stdint.h>
#include <stdbool.h>

#include "dtpm_client.h"
#include "dtpm_client_api.h"

#include "tfm_log.h"

struct tpm_chip_data tpm_chip_data = {
    .locality = 0,
    .timeout_msec_a = 750,
    .timeout_msec_b = 2000,
    .timeout_msec_c = 200,
    .timeout_msec_d = 30,
    .address = 0,
};


psa_status_t dtpm_client_extend(uint8_t pcr_index, uint8_t *value, uint16_t hash_alg, size_t hash_size)
{
    int status;

    tpm_interface_init(&tpm_chip_data, 0);

    /* Mode in this case means TPM_SU contants */
    tpm_startup(&tpm_chip_data, TPM_SU_CLEAR);

    status = tpm_pcr_extend(&tpm_chip_data, pcr_index, hash_alg, value, hash_size);
    if (status != TPM_SUCCESS) {
        tpm_interface_close(&tpm_chip_data, 0);
        ERROR("dTPM Client extend failed\n");
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    tpm_interface_close(&tpm_chip_data, 0);

    return PSA_SUCCESS;
}

psa_status_t tfm_dtpm_client_init(void)
{
    INFO_RAW("dTPM Client Partition initializing\n");

    /* TODO: Query boot measurements from desired slots
     * and extend into predetermined TPM PCR(s)
     */
    return PSA_SUCCESS;
}
