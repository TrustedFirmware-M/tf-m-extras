/*
 * Copyright (c) 2021-2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "vad_an552.h"

#include "psa/client.h"
#include "psa_manifest/sid.h"
#include "vad_an552_defs.h"

psa_status_t vad_an552_start_vad(void)
{
    psa_status_t status;

    status = psa_call(TFM_AN552_VAD_HANDLE, VAD_AN552_START,
                      NULL, 0, NULL, 0);

    return status;
}

psa_status_t vad_an552_query_vad(uint32_t* vad_status)
{
    psa_status_t status;
    psa_outvec out_vec[] = {
        {.base = vad_status, .len = sizeof(uint32_t)}
    };

    status = psa_call(TFM_AN552_VAD_HANDLE, VAD_AN552_QUERY,
                      NULL, 0, out_vec, IOVEC_LEN(out_vec));

    return status;
}

psa_status_t vad_an552_get_freq(uint32_t* freq)
{
    psa_status_t status;
    psa_outvec out_vec[] = {
        {.base = freq, .len = sizeof(uint32_t)}
    };

    status = psa_call(TFM_AN552_VAD_HANDLE, VAD_AN552_GET_FREQ,
                      NULL, 0, out_vec, IOVEC_LEN(out_vec));

    return status;
}

psa_status_t vad_an552_stop_vad(void)
{
    psa_status_t status;

    status = psa_call(TFM_AN552_VAD_HANDLE, VAD_AN552_STOP,
                      NULL, 0, NULL, 0);

    return status;
}
