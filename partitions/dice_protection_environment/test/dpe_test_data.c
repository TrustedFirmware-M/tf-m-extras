/*
 * Copyright (c) 2023-2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dice_protection_environment.h"
#include "dpe_test.h"
#include "dpe_test_data.h"
#include "dpe_test_private.h"

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
const struct dpe_derive_context_test_input_data_t derive_context_test_data_in_0[] = {
    {
       .id = FW_1, /* Caller/Parent FW_0, which is the RoT context */
       .cert_id = DPE_PLATFORM_CERT_ID,
       .use_parent_handle = false,
       .retain_parent_context = true,
       .allow_new_context_to_derive = true,
       .create_certificate = false,
       .dice_inputs = DICE_INPUT(0x11),
   },
   {
       .id = FW_2, /* Caller/Parent FW_1 */
       .cert_id = DPE_CERT_ID_SAME_AS_PARENT,
       .use_parent_handle = true,
       .retain_parent_context = true,
       .allow_new_context_to_derive = true,
       .create_certificate = false,
       .dice_inputs = DICE_INPUT(0x22),
   },
   {
       .id = FW_3, /* Caller/Parent FW_1 */
       .cert_id = DPE_CERT_ID_SAME_AS_PARENT,
       .use_parent_handle = true,
       .retain_parent_context = true,
       .allow_new_context_to_derive = true,
       .create_certificate = true, /* Finalise Platform certificate context */
       .dice_inputs = DICE_INPUT(0x33),
   },
};

struct dpe_derive_context_test_output_data_t
derive_context_test_data_out_0[ ARRAY_SIZE(derive_context_test_data_in_0) ] = {
    { INVALID_HANDLE, INVALID_HANDLE },
    { INVALID_HANDLE, INVALID_HANDLE },
    { INVALID_HANDLE, INVALID_HANDLE },
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
const struct dpe_derive_context_test_input_data_t derive_context_test_data_in_1[] = {
   {
       .id = FW_1, /* Caller/Parent FW_0, which is the RoT context */
       .cert_id = DPE_PLATFORM_CERT_ID,
       .use_parent_handle = false,
       .retain_parent_context = true,
       .allow_new_context_to_derive = true,
       .create_certificate = false,
       .dice_inputs = DICE_INPUT(0x11),
   },
};

struct dpe_derive_context_test_output_data_t
derive_context_test_data_out_1[ ARRAY_SIZE(derive_context_test_data_in_1) ] = {
    { INVALID_HANDLE, INVALID_HANDLE },
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
const struct dpe_derive_context_test_input_data_t derive_context_test_data_in_2[] = {
   {
       .id = FW_1, /* Caller/Parent FW_0, which is the RoT context */
       /* Not using cert_id */
       .use_parent_handle = false,
       .retain_parent_context = true,
       .allow_new_context_to_derive = true,
       .create_certificate = false,
       .dice_inputs = DICE_INPUT(0x11),
   },
   {
       .id = FW_2, /* Caller/Parent FW_1 */
       /* Not using cert_id */
       .use_parent_handle = true,
       .retain_parent_context = true,
       .allow_new_context_to_derive = true,
       .create_certificate = true,
       .dice_inputs = DICE_INPUT(0x22),
   },
   {
       .id = FW_3, /* Caller/Parent FW_1 */
       /* Not using cert_id */
       .use_parent_handle = true,
       .retain_parent_context = true,
       .allow_new_context_to_derive = true,
       .create_certificate = true,
       .dice_inputs = DICE_INPUT(0x33),
   },
};

struct dpe_derive_context_test_output_data_t
derive_context_test_data_out_2[ ARRAY_SIZE(derive_context_test_data_in_2) ] ={
    { INVALID_HANDLE, INVALID_HANDLE },
    { INVALID_HANDLE, INVALID_HANDLE },
    { INVALID_HANDLE, INVALID_HANDLE },
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
 *                  +=====|======|=========|=================+      +============+
 * +===========+    |     |      |         |    Cert #1      |      |   Cert #3  |
 * | RoT Cert  |    |     |      |         |   (w/o cert_id) |      |   (with    |
 * | (with     |    |     |      |         |                 |      |   cert_id) |
 * | cert_id)  |    |     |      |         |                 |      |            |
 * |  +-----+  |    |     |   +------+     |       +------+  |      |  +------+  |
 * |  |FW_0 | --------------> | FW_1 | ----------> | FW_2 | ---------> | FW_4 |  |
 * |  +-----+  |    |     |   +------+     |       +------+  |      |  +------+  |
 * |           |    |     |                |                 |      |            |
 * +===========+    |     +================+                 |      |            |
 *                  |                                        |      |            |
 *                  +========================================+      +============+
 */
const struct dpe_derive_context_test_input_data_t derive_context_test_data_in_3[] = {
   {
       .id = FW_1, /* Caller/Parent FW_0, which is the RoT context */
       /* Not using cert_id */
       .use_parent_handle = false,
       .retain_parent_context = true,
       .allow_new_context_to_derive = true,
       .create_certificate = false,     /* Cert #1 */
       .dice_inputs = DICE_INPUT(0x11),
   },
   {
       .id = FW_2, /* Caller/Parent FW_1 */
       /* Not using cert_id */
       .use_parent_handle = false,
       .retain_parent_context = true,
       .allow_new_context_to_derive = true,
       .create_certificate = true,
       .dice_inputs = DICE_INPUT(0x22),
   },
   {
       .id = FW_3, /* Caller/Parent FW_1 */
       /* Not using cert_id */
       .use_parent_handle = true,
       .retain_parent_context = true,
       .allow_new_context_to_derive = true,
       .create_certificate = true,         /* Cert #2 */
       .dice_inputs = DICE_INPUT(0x33),
   },
   {
       .id = FW_4, /* Caller/Parent FW_2 */
       .cert_id = DPE_PLATFORM_CERT_ID,
       .use_parent_handle = true,
       .retain_parent_context = true,
       .allow_new_context_to_derive = true,
       .create_certificate = true,         /* Cert #3 */
       .dice_inputs = DICE_INPUT(0x44),
   },
};

struct dpe_derive_context_test_output_data_t
derive_context_test_data_out_3[ ARRAY_SIZE(derive_context_test_data_in_3) ] = {
    { INVALID_HANDLE, INVALID_HANDLE },
    { INVALID_HANDLE, INVALID_HANDLE },
    { INVALID_HANDLE, INVALID_HANDLE },
    { INVALID_HANDLE, INVALID_HANDLE },
};

/*
 *                  Unfinished certificate context
 *                           (w/o cert_id)
 *                            (Leaf cert)
 *                            +------+
 *                            | FW_3 |
 *                            +------+
 *                               ^
 *                               |
 *                  +============|===========================+
 * +===========+    |            |              Cert #1      |
 * | RoT Cert  |    |            |             (w/o cert_id) |
 * | (with     |    |            |                           |
 * | cert_id)  |    |            |                           |
 * |  +-----+  |    |         +------+             +------+  |
 * |  |FW_0 | --------------> | FW_1 | ----------> | FW_2 |  |
 * |  +-----+  |    |         +------+             +------+  |
 * |           |    |                                        |
 * +===========+    |                                        |
 *                  |                                        |
 *                  +========================================+
 */
const struct dpe_derive_context_test_input_data_t derive_context_test_data_in_4[] = {
   {
       .id = FW_1, /* Caller/Parent FW_0, which is the RoT context */
       /* Not using cert_id */
       .use_parent_handle = false,
       .retain_parent_context = true,
       .allow_new_context_to_derive = true,
       .create_certificate = false,
       .dice_inputs = DICE_INPUT(0x11),
   },
   {
       .id = FW_2, /* Caller/Parent FW_1 */
       /* Not using cert_id */
       .use_parent_handle = true,
       .retain_parent_context = true,
       .allow_new_context_to_derive = true,
       .create_certificate = true,         /* Cert #1  */
       .dice_inputs = DICE_INPUT(0x22),
   },
   {
       .id = FW_3, /* Caller/Parent FW_1 */
       /* Not using cert_id */
       .use_parent_handle = true,
       .retain_parent_context = true,
       .allow_new_context_to_derive = true,
       .create_certificate = false,
       .dice_inputs = DICE_INPUT(0x33),
   },
};

struct dpe_derive_context_test_output_data_t
derive_context_test_data_out_4[ ARRAY_SIZE(derive_context_test_data_in_4) ] ={
    { INVALID_HANDLE, INVALID_HANDLE },
    { INVALID_HANDLE, INVALID_HANDLE },
    { INVALID_HANDLE, INVALID_HANDLE },
};

const struct dpe_test_data_t test_data[5] = {
    { derive_context_test_data_in_0, derive_context_test_data_out_0, ARRAY_SIZE(derive_context_test_data_in_0) },
    { derive_context_test_data_in_1, derive_context_test_data_out_1, ARRAY_SIZE(derive_context_test_data_in_1) },
    { derive_context_test_data_in_2, derive_context_test_data_out_2, ARRAY_SIZE(derive_context_test_data_in_2) },
    { derive_context_test_data_in_3, derive_context_test_data_out_3, ARRAY_SIZE(derive_context_test_data_in_3) },
    { derive_context_test_data_in_4, derive_context_test_data_out_4, ARRAY_SIZE(derive_context_test_data_in_4) },
};
