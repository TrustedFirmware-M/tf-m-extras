/*
 * Copyright (c) 2022-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "tfm_adac_api.h"
#include <stddef.h>
#include "psa/client.h"
#include "psa/error.h"
#include "psa_manifest/sid.h"

psa_status_t tfm_adac_service(uint32_t debug_request)
{
    psa_invec in_vec[] = {
        { .base = &debug_request, .len = sizeof(debug_request) }
    };

    return psa_call(TFM_ADAC_SERVICE_HANDLE,
                    0,
                    in_vec,
                    IOVEC_LEN(in_vec),
                    NULL,
                    0);
}