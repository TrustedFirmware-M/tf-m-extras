/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "dtpm_client.h"
#include "dtpm_client_api.h"
#include "platform/tpm_platform.h"

#include "measured_boot_api.h"
#include "measurement_metadata.h"

#include "psa/crypto.h"

#include "config_tfm.h"
#include "tfm_boot_measurement.h"
#include "dtpm_client_partition_hal.h"
#include "tfm_log.h"
#include "tfm_utils.h"

#include "event_record.h"
#include "event_print.h"

#ifndef TPM_INSTANCE_ID
#define TPM_INSTANCE_ID 0
#endif

/* Caller needs to check that `str` can fit in `event_name_buffer` */
#define APPEND_TO_EVENT_NAME(event_name_buffer, str, str_len, index)           \
do {                                                                           \
    memcpy(event_name_buffer + index, str, str_len);                           \
    index += str_len;                                                          \
} while (0)

static uint8_t event_log_buf[EVENT_LOG_BUFFER_SIZE] = {0};
static struct security_config *security_config_arr;

static const struct tpm_spi_plat *tpm_spi_plat;
static struct tpm_timeout_ops tpm_timeout_ops;

static const struct tpm_chip_timeouts tpm_timeouts = {
        .msec_a = 750,
        .msec_b = 2000,
        .msec_c = 200,
        .msec_d = 30,
};

static const struct tpm_chip_data tpm_chip_data = {
    .locality = 0,
    .timeouts = &tpm_timeouts,
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

psa_status_t dtpm_startup()
{
    int status;

    if (tpm_interface_init(tpm_spi_plat, &tpm_timeout_ops, &tpm_chip_data, 0)) {
        ERROR("%s: Interface init failed\n", __func__);
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    /* Mode in this case means TPM_SU contants */
    if (tpm_startup(&tpm_chip_data, TPM_SU_CLEAR)) {
        ERROR("%s: TPM startup failed\n", __func__);
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    tpm_interface_close(&tpm_chip_data, 0);

    return PSA_SUCCESS;
}

psa_status_t dtpm_client_extend(uint8_t pcr_index, uint8_t *value, uint16_t hash_alg,
                                size_t hash_size)
{
    int status;

    if (tpm_interface_init(tpm_spi_plat, &tpm_timeout_ops, &tpm_chip_data, 0)) {
        ERROR("%s: Interface init failed\n", __func__);
        return PSA_ERROR_HARDWARE_FAILURE;
    }

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

static int serialize_security_config_data(struct security_config_data *config_data,
                                          uint8_t *serialized_data_buf,
                                          size_t *serialized_data_len,
                                          size_t serialized_data_buf_len)
{
    size_t offset = 0;

    if (serialized_data_buf_len < sizeof(struct security_config_data)) {
        return -1;
    }

    memcpy(serialized_data_buf, &(config_data->name_length), sizeof(uint64_t));
    offset += sizeof(uint64_t);

    memcpy(serialized_data_buf + offset, &(config_data->data_length), sizeof(uint64_t));
    offset += sizeof(uint64_t);

    memcpy(serialized_data_buf + offset,
           &(config_data->name), config_data->name_length);
    offset += config_data->name_length;

    memcpy(serialized_data_buf + offset, &(config_data->config_data),
           config_data->data_length);
    offset += config_data->data_length;

    *serialized_data_len = offset;

    return 0;
}

static psa_status_t hash_platform_config_data(struct security_config_data *config_data,
                                              psa_algorithm_t hash_algo, uint8_t *digest_buf,
                                              size_t digest_buf_size, size_t *digest_len)
{
    size_t serialized_buf_len;
    uint8_t serialized_data_buf[sizeof(struct security_config_data)] = {0};

    if (digest_buf_size < PSA_HASH_LENGTH(hash_algo)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (serialize_security_config_data(config_data, serialized_data_buf,
                                       &serialized_buf_len,
                                       sizeof(serialized_data_buf))) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return(psa_hash_compute(hash_algo,
                            serialized_data_buf, serialized_buf_len,
                            digest_buf, digest_buf_size, digest_len));

}

static psa_status_t form_event_log_name(struct measurement_t *measurement, char *event_name,
                                        size_t event_name_size)
{
    size_t index = 0;

    if (measurement->metadata.sw_type_size > 0 && measurement->metadata.version_size > 0) {
        if (measurement->metadata.sw_type_size + strlen("-v") +  measurement->metadata.version_size
                + 1 > event_name_size) {
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }

        APPEND_TO_EVENT_NAME(event_name, measurement->metadata.sw_type,
                            measurement->metadata.sw_type_size, index);

        APPEND_TO_EVENT_NAME(event_name, "-v", strlen("-v"), index);

        APPEND_TO_EVENT_NAME(event_name, measurement->metadata.version,
                            measurement->metadata.version_size, index);

        event_name[index] = 0;
    } else {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return PSA_SUCCESS;
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

    if (tpm_plat_get_tpm_platform_config(&tpm_timeout_ops, &tpm_spi_plat, TPM_INSTANCE_ID)) {
        ERROR("%s: Invalid instance ID supplied\n", __func__);
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    psa_status_t status;
    int event_log_status;
    struct measurement_t measurement;
    bool is_locked;
    int8_t pcr_index;
    uint16_t hash_alg;
    int slot;
    event_log_metadata_t event_log_metadata;
    size_t security_config_digest_len;
    size_t security_config_len;
    const uint8_t *security_config_data_name;

    /* <SW_TYPE_STR>-v<VERSION_STR>\0 */
    char event_name[SW_TYPE_MAX_SIZE + VERSION_MAX_SIZE + 3] = {0};
    const uint16_t supported_algs[] = {TPM_ALG_SHA256};
    uint8_t security_config_digest_buf[MAX_DIGEST_SIZE] = {0};

    status = dtpm_startup();
    if (status) {
        return status;
    }

    if (event_log_init(event_log_buf, event_log_buf + sizeof(event_log_buf))) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    if (event_log_write_header(supported_algs, ARRAY_SIZE(supported_algs),
                               0, "", sizeof(""))) {
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
            ERROR("Extend to dTPM client failed\n");
            return status;
        }

        if (get_event_log_metadata_for_measurement_slot(slot, &event_log_metadata)) {
            return PSA_ERROR_PROGRAMMER_ERROR;
        }

        /* Form event name string using measured boot measurement metadata sw_type + version in
         * format `<SW_TYPE_STR>-v<VERSION_STR>`. If these are missing from the measured boot
         * metadata, fall back to using platform defined `name` supplied with `event_log_metadata`.
         */
        status = form_event_log_name(&measurement, &event_name, ARRAY_SIZE(event_name));
        if (status != PSA_SUCCESS) {
            if (ARRAY_SIZE(event_name) < strlen(event_log_metadata.name) + 1) {
                return PSA_ERROR_PROGRAMMER_ERROR;
            }

            memcpy(event_name, event_log_metadata.name, strlen(event_log_metadata.name) + 1);
        }

        event_log_status = event_log_write_pcr_event2_single(event_log_metadata.pcr,
                                                             EV_POST_CODE, hash_alg,
                                                             &measurement.value.hash_buf[0],
                                                             (const uint8_t *)event_name,
                                                             strlen(event_name) + 1);
        if (event_log_status) {
            ERROR("Event log record failed for measured boot metadata %d\n", event_log_status);
            return PSA_ERROR_PROGRAMMER_ERROR;
        }
    }

    if (tfm_plat_get_security_config_data(&security_config_arr,
                                          &security_config_len) != TFM_PLAT_ERR_SUCCESS) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    for (int i = 0; i < security_config_len; i++) {
        status = hash_platform_config_data(&security_config_arr[i].security_config_data,
                                           DTPM_CLIENT_PSA_HASH_ALG,
                                           security_config_digest_buf,
                                           sizeof(security_config_digest_buf),
                                           &security_config_digest_len);
        if (status != PSA_SUCCESS) {
            return status;
        }

        if (get_tpm_hash_alg(DTPM_CLIENT_PSA_HASH_ALG, &hash_alg)) {
            return PSA_ERROR_PROGRAMMER_ERROR;
        }

        status = dtpm_client_extend(security_config_arr[i].pcr_index,
                                    security_config_digest_buf,
                                    hash_alg, security_config_digest_len);
        if (status != PSA_SUCCESS) {
            ERROR("Extend to dTPM client failed\n");
            return status;
        }

        security_config_data_name = security_config_arr[i].security_config_data.name;

        event_log_status = event_log_write_pcr_event2_single(security_config_arr[i].pcr_index,
                                                             EV_SECURITY_CONFIG,
                                                             hash_alg, security_config_digest_buf,
                                                             security_config_data_name,
                                                             strlen(security_config_data_name) + 1);

        if (event_log_status) {
            ERROR("Event log record failed for security config data %d\n", event_log_status);
            return PSA_ERROR_PROGRAMMER_ERROR;
        }
    }

    event_log_dump(event_log_buf, get_event_log_size());

    return PSA_SUCCESS;
}
