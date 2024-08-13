/*
 * Copyright (c) 2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include "dice_protection_environment.h"
#include "dpe_client.h"
#include "dpe_context_mngr.h"
#include "dpe_cmd_decode.h"
#include "dpe_cmd_encode.h"

#include "cmd.h"
#include "root_keys.h"

#include "tfm_sp_log.h"

#define CLIENT_ID_NS -1

static void print_buf(const unsigned char *buf, size_t size)
{
    size_t i;

    if (buf != NULL) {
        for (i = 0; i < size; ++i) {
            if ((i & 0xF) == 0) {
                LOG_DBGFMT("\r\n");
            }
            if (buf[i] < 0x10) {
                LOG_DBGFMT(" 0%x", buf[i]);
            } else {
                LOG_DBGFMT(" %x", buf[i]);
            }
        }
    }
    LOG_DBGFMT("\r\n");
    LOG_DBGFMT("\r\n");
}

static dpe_error_t
cbor_cmd(const char *cmd_in_buf, size_t cmd_in_size, int *context_handle)
{
    char cmd_out_buf[2 * 4096];
    size_t cmd_out_size = sizeof(cmd_out_buf);
    dpe_error_t err;

    (void)context_handle;

    LOG_DBGFMT("DPE request (%ld):\n", cmd_in_size);
    print_buf(cmd_in_buf, cmd_in_size);

    err = dpe_command_decode(CLIENT_ID_NS,
                             cmd_in_buf, cmd_in_size,
                             cmd_out_buf, &cmd_out_size);

    LOG_DBGFMT("DPE response (%ld):\n", cmd_out_size);
    print_buf(cmd_out_buf, cmd_out_size);

    return err;
}

/*
 * DPE Library Init:
 * - crypto_lib
 * - platform
 * - context manager
 */
void dpe_lib_init(int *context_handle)
{
    int ret;
    dpe_error_t err;

    ret = psa_crypto_init();
    if (ret != 0) {
        printf("ERROR: Crypto init failed! (%d)\n", ret);
        exit(1);
    }

    ret = register_rot_cdi();
    if (ret != 0) {
        printf("ERROR: RoT CDI registration failed! (%d)\n", ret);
        exit(1);
    }

    ret = register_root_attest_key();
    if (ret != 0) {
        printf("ERROR: Root attest key registration failed! (%d)\n", ret);
        exit(1);
    }

    err = initialise_context_mngr(context_handle);
    if (err != DPE_NO_ERROR) {
        printf("ERROR: Context manager init failed (%d)\n", err);
        exit(1);
    }
}

dpe_error_t exec_dpe_cmd(enum cmd cmd, const char *cmd_in_buf,
                         size_t cmd_in_size, int *context_handle)
{
    switch(cmd) {
    case CBOR:
        return cbor_cmd(cmd_in_buf, cmd_in_size, context_handle);
    default:
        printf("ERROR: Unknown command\n");
        exit(1);
    }
}
