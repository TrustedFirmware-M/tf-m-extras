/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 */

#include <string.h>

#include "dtpm_client_api.h"

#include "psa/client.h"
#include "psa_manifest/sid.h"

psa_status_t tfm_dtpm_client_extend(uint8_t index, uint16_t algo, uint8_t *hash, size_t hash_size)
{

    psa_status_t status;

    struct pcr_extend_t pcr_extend = {
        .index = index,
        .hash_algo = algo,
        .hash_size = hash_size,
        .hash = {0},
    };

    memcpy(pcr_extend.hash, hash, hash_size);

    psa_invec in_vec[] = {
        {
            .base = &pcr_extend, .len  = sizeof(pcr_extend),
        }
    };

    status = psa_call(TFM_DTPM_CLIENT_HANDLE, TFM_DTPM_CLIENT_EXTEND,
                      in_vec, IOVEC_LEN(in_vec),
                      NULL, 0);

    return status;
}

psa_status_t tfm_get_event_log(uint8_t *buf, size_t buf_size, size_t *event_log_len)
{
    psa_status_t status;

    psa_outvec out_vec[] = {
        {
            .base = buf, .len = buf_size,
        },
        {
            .base = event_log_len, .len = sizeof(size_t),
        }
    };

    status = psa_call(TFM_DTPM_CLIENT_HANDLE, TFM_EVENT_LOG,
                      NULL, 0,
                      out_vec, IOVEC_LEN(out_vec));

    return status;
}
