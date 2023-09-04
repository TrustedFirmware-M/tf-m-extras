/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <string.h>

#include "dpe_boot_data.h"
#include "dpe_cmd_decode.h"
#include "dpe_context_mngr.h"
#include "psa/service.h"

#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define DPE_CMD_MAX_SIZE 4096

static char cmd_buf[DPE_CMD_MAX_SIZE];

psa_status_t tfm_dpe_init(void)
{
    dpe_error_t err;
    int context_handle;

    err = initialise_context_mngr(&context_handle);
    if (err != DPE_NO_ERROR) {
        return PSA_ERROR_GENERIC_ERROR;
    }

#ifndef DPE_TEST_MODE
    err = initialise_boot_data();
    if (err != DPE_NO_ERROR) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    err = derive_boot_data_contexts(context_handle, &context_handle);
    if (err != DPE_NO_ERROR) {
        return PSA_ERROR_GENERIC_ERROR;
    }
#endif

    /* TODO: share context handle */

    return PSA_SUCCESS;
}

psa_status_t tfm_dpe_service_sfn(const psa_msg_t *msg)
{
    int32_t err;
    size_t in_size = msg->in_size[0];
    size_t out_size = MIN(msg->out_size[0], sizeof(cmd_buf));

    /* DPE service does not support any non-zero message types */
    if (msg->type != 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (in_size > sizeof(cmd_buf)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (psa_read(msg->handle, 0, cmd_buf, in_size) != in_size) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    err = dpe_command_decode(msg->client_id, cmd_buf, in_size,
                             cmd_buf, &out_size);

    if (err == 0) {
        psa_write(msg->handle, 0, cmd_buf, out_size);
    }

    /* Clear the internal command buffer between calls */
    memset(cmd_buf, 0, sizeof(cmd_buf));

    return err;
}
