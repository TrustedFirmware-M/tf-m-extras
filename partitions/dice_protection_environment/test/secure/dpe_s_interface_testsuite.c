/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dpe_test.h"

static struct test_t dpe_s_tests[] = {
    {&derive_rot_layer_context, "DPE_S_TEST_INIT",
     "DPE derive RoT context"},
    {&derive_child_api_test, "DPE_S_TEST_1001",
     "DPE DeriveChild API"},
    {&certify_key_api_test, "DPE_S_TEST_1002",
     "DPE CertifyKey API"},
    {&derive_child_incorrect_handle_test, "DPE_S_TEST_1003",
     "DPE DeriveChild - invalid handle"},
    {&derive_child_invalid_hash_size_test, "DPE_S_TEST_1004",
     "DPE DeriveChild - invalid measurement descriptor size"},
    {&derive_child_invalid_signer_id_size_test, "DPE_S_TEST_1005",
     "DPE DeriveChild - invalid signer id descriptor size"},
    {&derive_child_invalid_config_desc_size_test, "DPE_S_TEST_1006",
     "DPE DeriveChild - invalid config descriptor size"},
    {&derive_child_missing_dice_input_arg_test, "DPE_S_TEST_1007",
     "DPE DeriveChild - missing required dice input arguments"},
    {&derive_child_invalid_cbor_encoded_input_test, "DPE_S_TEST_1008",
     "DPE DeriveChild - invalid cbor encoded input"},
    {&derive_child_single_use_handle_test, "DPE_S_TEST_1009",
     "DPE DeriveChild - same handle"},
    {&derive_child_core_functionality_test, "DPE_S_TEST_1010",
     "DPE DeriveChild functionality"},
    {&derive_child_with_parent_leaf_component_test, "DPE_S_TEST_1011",
     "DPE DeriveChild - Leaf component"},
};

void register_testsuite_extra_s_interface(struct test_suite_t *p_test_suite)
{
    uint32_t list_size;

    list_size = sizeof(dpe_s_tests) / sizeof(dpe_s_tests[0]);

    set_testsuite("DPE Secure Tests (DPE_S_TEST_1XXX)",
                  dpe_s_tests, list_size, p_test_suite);
}
