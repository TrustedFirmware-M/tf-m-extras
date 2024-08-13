/*
 * Copyright (c) 2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef _CMD_H_
#define _CMD_H_

enum cmd {
    CBOR, /* CBOR encoded */
    MAX_CMD_VAL
};

int exec_dpe_cmd(enum cmd cmd, const char *cmd_in_buf, size_t cmd_in_size, int *context_handle);

void dpe_lib_init(int *context_handle);

#endif /* _CMD_H_ */
