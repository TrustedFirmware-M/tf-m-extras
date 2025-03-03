/*
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdint.h>

#include "psa/service.h"
#include "psa_manifest/tfm_example_partition.h"
#include "tfm_log_unpriv.h"

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
        INFO_UNPRIV_RAW("[Example partition] Service called! arg=%x\n", arg);

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
    INFO_UNPRIV_RAW("Example Partition initializing\n");

    return PSA_SUCCESS;
}
