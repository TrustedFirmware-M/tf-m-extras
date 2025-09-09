/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 */

#include "psa/service.h"
#include "tfm_log_unpriv.h"

#include "dtpm_client.h"
#include "dtpm_client_api.h"

static uint8_t ev_log_buff[EVENT_LOG_BUFFER_SIZE] = {0};

static psa_status_t extend_pcr(const psa_msg_t *msg)
{
    psa_status_t status;
    struct pcr_extend_t pcr_extend_in;
    size_t num;

    /* Check input parameter */
    if (msg->in_size[0] != sizeof(pcr_extend_in) ) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    num = psa_read(msg->handle, 0, &pcr_extend_in, sizeof(pcr_extend_in));
    if (num != sizeof(pcr_extend_in)) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    /* Check we're not writing to a PCR index beyond 24 */
    if (pcr_extend_in.index > 24) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = dtpm_client_extend(pcr_extend_in.index, pcr_extend_in.hash, pcr_extend_in.hash_algo,
                                pcr_extend_in.hash_size);

    return status;
}

static psa_status_t event_log_buf(const psa_msg_t *msg)
{

    size_t ev_log_size;

    if (get_event_log(ev_log_buff, EVENT_LOG_BUFFER_SIZE, &ev_log_size) != PSA_SUCCESS) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    if (msg->out_size[0] < ev_log_size) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    psa_write(msg->handle, 0, ev_log_buff, ev_log_size);
    psa_write(msg->handle, 1, &ev_log_size, sizeof(ev_log_size));

    return PSA_SUCCESS;
}

psa_status_t tfm_dtpm_client_sfn(const psa_msg_t *msg)
{
    psa_status_t status;

    /* Decode the message */
    switch (msg->type) {
        case TFM_DTPM_CLIENT_EXTEND:
            status = extend_pcr(msg);
            break;

        case TFM_EVENT_LOG:
            status = event_log_buf(msg);
            break;

        default:
            /* Invalid message type */
            status = PSA_ERROR_PROGRAMMER_ERROR;
            break;
    }

    return status;
}
