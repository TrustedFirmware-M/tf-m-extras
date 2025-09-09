/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "dtpm_client.h"
#include "dtpm_client_api.h"
#include "measured_boot_api.h"
#include "measurement_metadata.h"
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"
#include "tfm_boot_measurement.h"
#include "event_log.h"

#include "tfm_log.h"

static uint8_t event_log_buf[EVENT_LOG_BUFFER_SIZE] = {0};

struct tpm_chip_data tpm_chip_data = {
    .locality = 0,
    .timeout_msec_a = 750,
    .timeout_msec_b = 2000,
    .timeout_msec_c = 200,
    .timeout_msec_d = 30,
    .address = 0,
};

static void initialise_measurement(struct measurement_t *measurement)
{
    (void)memset(measurement, 0, (sizeof(struct measurement_t)));
    measurement->value.hash_buf_size = MEASUREMENT_VALUE_MAX_SIZE;
    measurement->metadata.signer_id_size = SIGNER_ID_MAX_SIZE;
    measurement->metadata.version_size = VERSION_MAX_SIZE;
    measurement->metadata.sw_type_size = SW_TYPE_MAX_SIZE;
}

static psa_status_t read_mb_measurement(uint8_t slot_index,
                              struct measurement_t *measurement,
                              bool *is_locked)
{
    psa_status_t status;
    size_t signer_id_len, version_len, sw_type_len;
    size_t measurement_value_len;

    status = tfm_measured_boot_read_measurement(
                                    slot_index,
                                    &measurement->metadata.signer_id[0],
                                    measurement->metadata.signer_id_size,
                                    &signer_id_len,
                                    &measurement->metadata.version[0],
                                    measurement->metadata.version_size,
                                    &version_len,
                                    &measurement->metadata.measurement_algo,
                                    &measurement->metadata.sw_type[0],
                                    measurement->metadata.sw_type_size,
                                    &sw_type_len,
                                    &measurement->value.hash_buf[0],
                                    measurement->value.hash_buf_size,
                                    &measurement_value_len,
                                    is_locked);

    if (status != PSA_SUCCESS) {
        return status;
    }

    /* update to reflect correct sizes */
    measurement->metadata.signer_id_size = signer_id_len;
    measurement->metadata.version_size = version_len;
    measurement->metadata.sw_type_size = sw_type_len;
    measurement->value.hash_buf_size = measurement_value_len;

    return PSA_SUCCESS;
}

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

static int get_tpm_hash_alg(uint32_t psa_algo, uint16_t *hash_alg)
{
    switch (psa_algo) {
    case PSA_ALG_SHA_256:
        *hash_alg = TPM_ALG_SHA256;
        return 0;
    default:
        return -1;
    }
}

static size_t get_event_log_size()
{
     return event_log_get_cur_size(event_log_buf);
}

psa_status_t get_event_log(uint8_t *buffer, size_t buffer_size, size_t *event_log_size)
{
    size_t ev_log_size = get_event_log_size(event_log_buf);

    if (buffer == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (buffer_size < ev_log_size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    memcpy(buffer, event_log_buf, ev_log_size);

    *event_log_size = ev_log_size;

    return PSA_SUCCESS;
}

psa_status_t tfm_dtpm_client_init(void)
{
    INFO_RAW("dTPM Client Partition initializing\n");

    psa_status_t status;
    struct measurement_t measurement;
    bool is_locked;
    int8_t pcr_index;
    uint16_t hash_alg;
    int slot;
    event_log_metadata_t event_log_metadata;

    if (init_pcr_index_for_boot_measurement()) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    if (event_log_init(event_log_buf, event_log_buf + sizeof(event_log_buf))) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    if (event_log_write_header()) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    /* Lowest possible slot number is Zero */
    for (slot = 0; slot < BOOT_MEASUREMENT_SLOT_MAX; slot++) {
        pcr_index = get_pcr_index_for_boot_measurement(slot);
        if (pcr_index < 0) {
            continue;
        }

        initialise_measurement(&measurement);
        status = read_mb_measurement(slot, &measurement, &is_locked);
        if (status != PSA_SUCCESS) {
            if (status == PSA_ERROR_DOES_NOT_EXIST) {
                INFO("Measurement not found at slot %d\n", slot);
                continue;
            }
            return status;
        }

        if (get_tpm_hash_alg(measurement.metadata.measurement_algo, &hash_alg) != 0) {
            return PSA_ERROR_PROGRAMMER_ERROR;
        }

        status = dtpm_client_extend(pcr_index, &measurement.value.hash_buf[0],
                hash_alg, measurement.value.hash_buf_size);
        if (status != PSA_SUCCESS) {
            return status;
        }

        if (get_event_log_metadata_for_measurement_slot(slot, &event_log_metadata)) {
            return PSA_ERROR_PROGRAMMER_ERROR;
        }

        if (event_log_record(&measurement.value.hash_buf[0], EV_POST_CODE, &event_log_metadata)) {
            ERROR("Event log record failed\n");
            return PSA_ERROR_PROGRAMMER_ERROR;
        }
    }

    return PSA_SUCCESS;
}
