/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dpe_client.h"

#include "psa/client.h"
#include "psa_manifest/sid.h"

int32_t dpe_client_call(const char *cmd_input, size_t cmd_input_size,
                        char *cmd_output, size_t *cmd_output_size)
{
    int32_t err;

    psa_invec in_vec[] = {
        { cmd_input, cmd_input_size },
    };
    psa_outvec out_vec[] = {
        { cmd_output, *cmd_output_size },
    };

    err = psa_call(TFM_DPE_SERVICE_HANDLE, 0, in_vec, IOVEC_LEN(in_vec),
                   out_vec, IOVEC_LEN(out_vec));

    *cmd_output_size = out_vec[0].len;

    return err;
}
