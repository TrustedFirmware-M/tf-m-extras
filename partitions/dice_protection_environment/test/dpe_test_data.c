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

/* Below dataset is used for CertifyKey command test
 *
 *                      +====================================+
 *                      |  Platform Cert (DPE_PLATFORM_CERT) |
 *                      |                                    |
 *                      |                                    |
 *                      |     +------+                       |
 *                      |     | FW_3 |                       |
 *                      |     +------+                       |
 *                      |        ^                           |
 *                      |        |                           |
 *                      |        |                           |
 * +=============+      |        |                           |
 * |  RoT Cert   |      |        |                           |
 * |             |      |        |                           |
 * | +---------+ |      |    +------+        +------+        |
 * | |  FW_0   |-|-------->  | FW_1 | -----> | FW_2 |        |
 * | +---------+ |      |    +------+        +------+        |
 * |             |      |                                    |
 * +=============+      +====================================+
 */
const struct dpe_derive_context_test_data_t
    derive_context_test_dataset_1[DERIVE_CONTEXT_TEST_DATA1_SIZE] = {
    {
        {
            .cert_id = DPE_PLATFORM_CERT_ID,
            .use_parent_handle = false,
            .retain_parent_context = true,
            .allow_new_context_to_derive = true,
            .create_certificate = false,
        },
    },
    {
        {
            .cert_id = DPE_CERT_ID_SAME_AS_PARENT,
            .use_parent_handle = true,
            .retain_parent_context = true,
            .allow_new_context_to_derive = true,
            .create_certificate = false,
        },
    },
    {
        {
            .cert_id = DPE_CERT_ID_SAME_AS_PARENT,
            .use_parent_handle = true,
            .retain_parent_context = true,
            .allow_new_context_to_derive = true,
            .create_certificate = true, /* Finalise Platform certificate context */
        },
    },
};

/* Below dataset is used for CertifyKey command test
 *
 * +=============+
 * |  RoT Cert   |        Unfinished certificate context
 * |             |
 * | +---------+ |          +------+
 * | |  FW_0   |-|------->  | FW_1 |
 * | +---------+ |          +------+
 * |             |
 * +=============+
 */
const struct dpe_derive_context_test_data_t derive_context_test_dataset_2 = {
    {
        .cert_id = DPE_PLATFORM_CERT_ID,
        .use_parent_handle = false,
        .retain_parent_context = true,
        .allow_new_context_to_derive = true,
        .create_certificate = false,
    },
};

/*
 *                        +================+
 *                        |    Cert #2     |
 *                        | (w/o cert_id)  |
 *                        |   +------+     |
 *                        |   | FW_3 |     |
 *                        |   +------+     |
 *                        |      ^         |
 *                        |      |         |
 *                  +=====|======|=========|=================+
 * +===========+    |     |      |         |    Cert #1      |
 * | RoT Cert  |    |     |      |         |   (w/o cert_id) |
 * | (with     |    |     |      |         |                 |
 * | cert_id)  |    |     |      |         |                 |
 * |  +-----+  |    |     |   +------+     |       +------+  |
 * |  |FW_0 | --------------> | FW_1 | ----------> | FW_2 |  |
 * |  +-----+  |    |     |   +------+     |       +------+  |
 * |           |    |     |                |                 |
 * +===========+    |     +================+                 |
 *                  |                                        |
 *                  +========================================+
 */
const struct dpe_derive_context_test_data_t
    derive_context_test_dataset_3[DERIVE_CONTEXT_TEST_DATA3_SIZE] = {
    {
        {
            /* Not using cert_id */
            .use_parent_handle = false,
            .retain_parent_context = true,
            .allow_new_context_to_derive = true,
            .create_certificate = false,
        },
    },
    {
        {
            /* Derive FW_2, Caller/Parent FW_1 */
            /* Not using cert_id */
            .use_parent_handle = true,
            .retain_parent_context = true,
            .allow_new_context_to_derive = true,
            .create_certificate = true,
        },
    },
    {
        {
            /* Derive FW_3, Caller/Parent FW_1 */
            /* Not using cert_id */
            .use_parent_handle = true,
            .retain_parent_context = true,
            .allow_new_context_to_derive = true,
            .create_certificate = true,
        },
    },
};
