/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <string.h>
#include "measured_boot.h"
#include "measured_boot_defs.h"
#include "tfm_sp_log.h"

#include "psa/service.h"
#include "psa_manifest/pid.h"
#include "psa/crypto.h"
#include "psa_manifest/tfm_measured_boot.h"

/* TODO: This info will be used later on as input to decide access control */
static int32_t g_measured_boot_caller_id;

static psa_status_t read_measurements(const psa_msg_t *msg)
{
    struct measured_boot_read_iovec_in_t read_iov_in;
    struct measured_boot_read_iovec_out_t read_iov_out;
    size_t signer_id_len, measurement_value_len;
    size_t num;
    size_t signer_id_size, measurement_value_size;
    uint8_t signer_id[SIGNER_ID_MAX_SIZE] = {0};
    uint8_t measurement_value[MEASUREMENT_VALUE_SIZE] = {0};
    psa_status_t status;

    /* store the client ID here for later use in service */
    g_measured_boot_caller_id = msg->client_id;

    signer_id_size = msg->out_size[1];
    measurement_value_size = msg->out_size[2];

    /* Check input parameter */
    if ((msg->in_size[0] != sizeof(struct measured_boot_read_iovec_in_t)) ||
        (msg->out_size[0] != sizeof(struct measured_boot_read_iovec_out_t))) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    num = psa_read(msg->handle, 0, &read_iov_in, sizeof(read_iov_in));
    if (num != sizeof(read_iov_in)) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    /* Validate requested slot number */
    if (read_iov_in.index >= NUM_OF_MEASUREMENT_SLOTS) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    memset(&read_iov_out, 0, sizeof(read_iov_out));

    status = measured_boot_read_measurement(read_iov_in.index,
                                            &signer_id[0],
                                            signer_id_size,
                                            &signer_id_len,
                                            &read_iov_out.version[0],
                                            read_iov_in.version_size,
                                            &read_iov_out.version_len,
                                            &read_iov_out.measurement_algo,
                                            &read_iov_out.sw_type[0],
                                            read_iov_in.sw_type_size,
                                            &read_iov_out.sw_type_len,
                                            &measurement_value[0],
                                            measurement_value_size,
                                            &measurement_value_len,
                                            &read_iov_out.is_locked);

    if (status == PSA_SUCCESS) {
        psa_write(msg->handle, 0, &read_iov_out, sizeof(read_iov_out));
        psa_write(msg->handle, 1, &signer_id[0], signer_id_len);
        psa_write(msg->handle, 2, &measurement_value[0], measurement_value_len);
    }

    return status;
}

static psa_status_t extend_measurement(const psa_msg_t *msg)
{
    struct measured_boot_extend_iovec_t extend_iov;
    size_t num;
    size_t signer_id_size;
    size_t version_size;
    size_t measurement_value_size;
    uint8_t signer_id[SIGNER_ID_MAX_SIZE] = {0};
    uint8_t version[VERSION_MAX_SIZE] = {0};
    uint8_t measurement_value[MEASUREMENT_VALUE_MAX_SIZE] = {0};

    /* store the client ID here for later use in service */
    g_measured_boot_caller_id = msg->client_id;

    /* Check input parameter */
    if (msg->in_size[0] != sizeof(struct measured_boot_extend_iovec_t)) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    signer_id_size = msg->in_size[1];
    version_size = msg->in_size[2];
    measurement_value_size = msg->in_size[3];

    memset(&extend_iov, 0, sizeof(extend_iov));
    num = psa_read(msg->handle, 0, &extend_iov,
                   sizeof(struct measured_boot_extend_iovec_t));
    if (num != sizeof(struct measured_boot_extend_iovec_t)) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    /* Validate size limits of input parameters */
    if ((signer_id_size < SIGNER_ID_MIN_SIZE)                 ||
        (signer_id_size > SIGNER_ID_MAX_SIZE)                 ||
        (version_size > VERSION_MAX_SIZE)                     ||
        (measurement_value_size < MEASUREMENT_VALUE_MIN_SIZE) ||
        (measurement_value_size > MEASUREMENT_VALUE_MAX_SIZE) ||
        (extend_iov.sw_type_size > SW_TYPE_MAX_SIZE)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Validate requested slot number */
    if (extend_iov.index >= NUM_OF_MEASUREMENT_SLOTS) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    num = psa_read(msg->handle, 1, signer_id, signer_id_size);
    if (num != signer_id_size) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    num = psa_read(msg->handle, 2, version, version_size);
    if (num != version_size) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    num = psa_read(msg->handle, 3, &measurement_value[0],
                   measurement_value_size);
    if (num != measurement_value_size) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    return measured_boot_extend_measurement(extend_iov.index,
                                            signer_id,
                                            signer_id_size,
                                            version,
                                            version_size,
                                            extend_iov.measurement_algo,
                                            &extend_iov.sw_type[0],
                                            extend_iov.sw_type_size,
                                            measurement_value,
                                            measurement_value_size,
                                            extend_iov.lock_measurement);
}

static void measured_boot_signal_handle(psa_signal_t signal)
{
    psa_status_t status;
    psa_msg_t msg;

    /* Retrieve the message corresponding to the measured_boot service signal */
    status = psa_get(signal, &msg);
    if (status != PSA_SUCCESS) {
        return;
    }

    /* Decode the message */
    switch (msg.type) {
    case TFM_MEASURED_BOOT_READ:
        status = read_measurements(&msg);
        /* Reply with the message result status to unblock the client */
        psa_reply(msg.handle, status);
        break;
    case TFM_MEASURED_BOOT_EXTEND:
        status = extend_measurement(&msg);
        /* Reply with the message result status to unblock the client */
        psa_reply(msg.handle, status);
        break;
    default:
        /* Invalid message type */
        status = PSA_ERROR_NOT_SUPPORTED;
        break;
    }
}

/**
 * \brief The measured_boot partition's entry function.
 */
psa_status_t tfm_measured_boot_init(void)
{
    psa_status_t status = PSA_SUCCESS;

    /* Initialise all measurements & related metadata */
    initialise_all_measurements();

    LOG_DBGFMT("Measured Boot : selected algorithm: %x\r\n",
               TFM_MEASURED_BOOT_HASH_ALG);

#ifdef CONFIG_TFM_BOOT_STORE_MEASUREMENTS
    status = collect_shared_measurements();
#endif

    if (status != PSA_SUCCESS) {
        psa_panic();
    }

    psa_signal_t signals = 0;

    while (1) {
        signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);
        if (signals & TFM_MEASURED_BOOT_SIGNAL) {
            measured_boot_signal_handle(TFM_MEASURED_BOOT_SIGNAL);
        } else {
            psa_panic();
        }
    }
}
