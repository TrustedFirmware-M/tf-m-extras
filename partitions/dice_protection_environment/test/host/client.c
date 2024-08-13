/*
 * Copyright (c) 2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dpe_client.h"
#include "dpe_cmd_decode.h"

#define CLIENT_ID_NS -1

int32_t dpe_client_call(const char *cmd_input, size_t cmd_input_size,
                        char *cmd_output, size_t *cmd_output_size)
{
    int32_t err;

    err = dpe_command_decode(CLIENT_ID_NS,
                             cmd_input, cmd_input_size,
                             cmd_output, cmd_output_size);

    return err;
}
