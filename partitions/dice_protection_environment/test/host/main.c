/*
 * Copyright (c) 2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include "dice_protection_environment.h"
#include "tfm_sp_log.h"

#include "cmd.h"

static int read_cmd(const char path[], char *cmd_buf, size_t *cmd_buf_size)
{
    FILE *fd;
    size_t cmd_size;

    if ((fd = fopen(path, "r")) == NULL) {
        printf("ERROR: File (%s) cannot be opened.\n", path);
        return -1;
    }

    fseek(fd, 0, SEEK_END);
    cmd_size = ftell(fd);
    rewind(fd);

    if (*cmd_buf_size < cmd_size) {
        printf("ERROR: cmd_buf is too small\n");
        return -1;
    }

    for (size_t i = 0; i < cmd_size; ++i) {
        cmd_buf[i] = fgetc(fd);
    }
    *cmd_buf_size = cmd_size;

    fclose(fd);

    return 0;
}

int main(int argc, char **argv)
{
    int context_handle;
    int ret;
    char cmd_in_buf[4096] = {0};
    size_t cmd_in_size = sizeof(cmd_in_buf);
    dpe_error_t err;

    dpe_lib_init(&context_handle);

    if (argc == 2) {
        ret = read_cmd(argv[1], cmd_in_buf, &cmd_in_size);
        if (ret < 0) {
            exit(1);
        }

        err = exec_dpe_cmd(CBOR, cmd_in_buf, cmd_in_size, &context_handle);
        if (err != DPE_NO_ERROR) {
            printf("DPE command decode/execution failed (%d)\n", ret);
            exit(1);
        }
    } else {
        printf("Wrong number of input params! It must be 1!\n");
        exit(1);
    }

    exit(0);
}
