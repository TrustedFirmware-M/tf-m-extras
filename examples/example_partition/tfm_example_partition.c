/*
 * Copyright (c) 2020-2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdint.h>

#include "psa/service.h"
#include "psa_manifest/tfm_example_partition.h"
#include "tfm_sp_log.h"

/**
 * \brief An example service implementation that prints out an argument from the
 *        client.
 */
psa_status_t tfm_example_service_sfn(const psa_msg_t *msg)
{
    psa_status_t status;
    uint32_t arg;

    /* Decode the message */
    switch (msg->type) {
    case PSA_IPC_CONNECT:
    case PSA_IPC_DISCONNECT:
        /*
         * This service does not require any setup or teardown on connect or
         * disconnect, so just reply with success.
         */
        status = PSA_SUCCESS;
        break;
    case PSA_IPC_CALL:
        if (msg->in_size[0] != sizeof(arg)) {
            status = PSA_ERROR_PROGRAMMER_ERROR;
            break;
        }

        /* Print arg from client */
        psa_read(msg->handle, 0, &arg, sizeof(arg));
        LOG_INFFMT("[Example partition] Service called! arg=%p\r\n", arg);

        status = PSA_SUCCESS;
        break;
    default:
        /* Invalid message type */
        status = PSA_ERROR_PROGRAMMER_ERROR;
        break;
    }

    return status;
}

/**
 * \brief The example partition's entry function.
 */
psa_status_t tfm_example_partition_main(void)
{
    LOG_INFFMT("Example Partition initializing\r\n");

    return PSA_SUCCESS;
}
