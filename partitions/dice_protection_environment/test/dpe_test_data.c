/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dice_protection_environment.h"
#include "dpe_test_data.h"

int retained_rot_ctx_handle;

/* Below dataset is used for CertifyKey command test */
const struct dpe_derive_context_test_data_t
    derive_context_test_dataset_1[DERIVE_CONTEXT_TEST_DATA1_SIZE] = {
    {
        {
            /* Derive RSS_BL2, Caller/Parent RSS BL1_2 */
            .use_parent_handle = false,
            .retain_parent_context = true,
            .allow_new_context_to_derive = true,
            .create_certificate = false,
        },
    },
    {
        {
            /* Derive SCP_BL1 (1st derived context of RSS BL2) */
            .use_parent_handle = true,
            .retain_parent_context = true,
            .allow_new_context_to_derive = false,
            .create_certificate = false,
        },
    },
    {
        {
            /* Derive AP_BL1, (2nd and final derived context of RSS BL2) */
            .use_parent_handle = true,
            .retain_parent_context = true,
            .allow_new_context_to_derive = true,
            .create_certificate = true, /* Finalise Platform layer */
        },
    },
};

/* Below dataset is used for CertifyKey command test */
const struct dpe_derive_context_test_data_t derive_context_test_dataset_2 = {
    {
        /* Derive RSS_BL2, Caller/Parent RSS BL1_2 */
        .use_parent_handle = false,
        .retain_parent_context = true,
        .allow_new_context_to_derive = true,
        .create_certificate = false,
    },
};
