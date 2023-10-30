/*
 * Copyright (c) 2022-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdint.h>
#include <stdbool.h>
#include "adac.h"
#include "psa/error.h"
#include "psa/service.h"
#include "psa_manifest/pid.h"
#include "tfm_adac_api.h"

static bool is_service_enabled;

static psa_status_t adac_service(const psa_msg_t *msg)
{
    uint32_t debug_request;
    size_t num;

    /* Check input parameter */
    if (msg->in_size[0] != sizeof(debug_request)) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    num = psa_read(msg->handle, 0, &debug_request, sizeof(debug_request));
    if (num != sizeof(debug_request)) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    return adac_service_request(debug_request);
}

/**
 * \brief The ADAC partition's entry function.
 */
psa_status_t tfm_adac_init(void)
{
    return adac_sp_init(&is_service_enabled);
}

psa_status_t tfm_adac_service_sfn(const psa_msg_t *msg)
{
    if (!is_service_enabled) {
        return PSA_ERROR_NOT_PERMITTED;
    }

    /* Process the message type */
    switch (msg->type) {
    case 0:
        return adac_service(msg);
    default:
        /* Invalid message type */
        return PSA_ERROR_NOT_SUPPORTED;
    }
}
