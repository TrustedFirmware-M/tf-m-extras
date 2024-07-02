/*
 * Copyright (c) 2023-2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dice_protection_environment.h"
#include "dpe_test_data.h"
#include "dpe_test.h"

int retained_rot_ctx_handle;

/* Below dataset is used for CertifyKey command test */
const struct dpe_derive_context_test_data_t
    derive_context_test_dataset_1[DERIVE_CONTEXT_TEST_DATA1_SIZE] = {
    {
        {
            /* Derive RSE_BL2, Caller/Parent RSE BL1_2 */
            .cert_id = DPE_PLATFORM_CERT_ID,
            .use_parent_handle = false,
            .retain_parent_context = true,
            .allow_new_context_to_derive = true,
            .create_certificate = false,
        },
    },
    {
        {
            /* Derive SCP_BL1 (1st derived context of RSE BL2) */
            .cert_id = DPE_CERT_ID_SAME_AS_PARENT,
            .use_parent_handle = true,
            .retain_parent_context = true,
            .allow_new_context_to_derive = true,
            .create_certificate = false,
        },
    },
    {
        {
            /* Derive AP_BL1, (2nd and final derived context of RSE BL2) */
            .cert_id = DPE_CERT_ID_SAME_AS_PARENT,
            .use_parent_handle = true,
            .retain_parent_context = true,
            .allow_new_context_to_derive = true,
            .create_certificate = true, /* Finalise Platform certificate context */
        },
    },
};

/* Below dataset is used for CertifyKey command test */
const struct dpe_derive_context_test_data_t derive_context_test_dataset_2 = {
    {
        /* Derive RSE_BL2, Caller/Parent RSE BL1_2 */
        .cert_id = DPE_PLATFORM_CERT_ID,
        .use_parent_handle = false,
        .retain_parent_context = true,
        .allow_new_context_to_derive = true,
        .create_certificate = false,
    },
};
