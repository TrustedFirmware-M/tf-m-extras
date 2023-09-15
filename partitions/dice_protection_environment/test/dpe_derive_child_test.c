/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <string.h>
#include "dice_protection_environment.h"
#include "dpe_test.h"
#include "dpe_test_data.h"

extern struct dpe_derive_child_test_data_t derive_child_test_dataset_1[DERIVE_CHILD_TEST_DATA1_SIZE];
extern int last_retained_child_handle;

void derive_child_api_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int out_child_handle;
    int out_parent_handle;
    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;

    dpe_err = dpe_derive_child(last_retained_child_handle,
                               false, /* retain_parent_context */
                               true,  /* allow_child_to_derive */
                               false, /* create_certificate */
                               &dice_inputs,
                               &out_child_handle,
                               &out_parent_handle);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveChild call failed");
        return;
    }

    TEST_LOG("out_child_handle = %d\r\n", out_child_handle);
    TEST_LOG("out_parent_handle = %d\r\n", out_parent_handle);

    /* Save the last handle for the subsequent test */
    last_retained_child_handle = out_child_handle;

    ret->val = TEST_PASSED;
}

void derive_rot_layer_context(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;
    int out_parent_handle;

    dpe_err = dpe_derive_child(ROT_CTX_HANDLE,
                               false, /* retain_parent_context */
                               true,  /* allow_child_to_derive */
                               true,  /* create_certificate */
                               &dice_inputs,
                               &last_retained_child_handle,
                               &out_parent_handle);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveChild RoT context init failed");
        return;
    }

    ret->val = TEST_PASSED;
}

static void call_derive_child_with_test_data(
                        struct test_result_t *ret,
                        struct dpe_derive_child_test_data_t *test_data,
                        int test_count)
{
    dpe_error_t dpe_err;
    int i, in_handle, out_child_handle, out_parent_handle;
    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;
    int test_out_handles[MAX_NUM_OF_COMPONENTS] = {0};

    for (i = 0; i < test_count; i++) {
        test_data = &derive_child_test_dataset_1[i];

        in_handle = (i == 0) ? last_retained_child_handle :
                               test_out_handles[test_data->inputs.in_handle_comp_idx];

        dpe_err = dpe_derive_child(in_handle,
                                   test_data->inputs.retain_parent_context,
                                   test_data->inputs.allow_child_to_derive,
                                   test_data->inputs.create_certificate,
                                   &dice_inputs,
                                   &out_child_handle,
                                   &out_parent_handle);

        if (dpe_err != DPE_NO_ERROR) {
            TEST_FAIL("DPE DeriveChild core functionality test failed");
            return;
        }

        if ((GET_IDX(out_child_handle) == GET_IDX(out_parent_handle)) &&
            (out_child_handle != INVALID_HANDLE)) {
            TEST_FAIL("DPE DeriveChild core test failed,"
                      "Child & parent handle cannot share same component");
            return;
        }

        if ((GET_IDX(out_child_handle) != test_data->outputs.expected_child_handle_idx) ||
            (GET_IDX(out_parent_handle) != test_data->outputs.expected_parent_handle_idx)) {
            TEST_FAIL("DPE DeriveChild core test failed, actual output not as expected");
            return;
        }

        if (test_data->inputs.retain_parent_context) {
            test_out_handles[GET_IDX(out_parent_handle)] = out_parent_handle;
        }

        if (test_data->inputs.allow_child_to_derive) {
            test_out_handles[GET_IDX(out_child_handle)] = out_child_handle;
        }
    }

    /* Save the last handle for the subsequent test */
    last_retained_child_handle = out_child_handle;

    ret->val = TEST_PASSED;
}

void derive_child_core_functionality_test(struct test_result_t *ret)
{
    int test_count;
    struct dpe_derive_child_test_data_t *test_data;

    test_data = &derive_child_test_dataset_1[0];
    test_count = sizeof(derive_child_test_dataset_1)/sizeof(derive_child_test_dataset_1[0]);

    call_derive_child_with_test_data(ret, test_data, test_count);
}

void derive_child_single_use_handle_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int out_child_handle;
    int out_parent_handle;
    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;

    dpe_err = dpe_derive_child(last_retained_child_handle,
                               false, /* retain_parent_context */
                               true,  /* allow_child_to_derive */
                               false, /* create_certificate */
                               &dice_inputs,
                               &out_child_handle,
                               &out_parent_handle);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveChild call failed");
        return;
    }

    /* Use the same handle again */
    dpe_err = dpe_derive_child(last_retained_child_handle,
                               false, /* retain_parent_context */
                               true,  /* allow_child_to_derive */
                               false, /* create_certificate */
                               &dice_inputs,
                               &out_child_handle,
                               &out_parent_handle);
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveChild test: Same handle used again should return invalid argument");
        return;
    }

    /* Save the last handle for the subsequent test */
    last_retained_child_handle = out_child_handle;

    ret->val = TEST_PASSED;
}
void derive_child_incorrect_handle_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int out_child_handle, out_parent_handle, invalid_handle;
    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;

    /* Use a different handle index */
    invalid_handle = last_retained_child_handle;
    invalid_handle = SET_IDX(invalid_handle, (GET_IDX(last_retained_child_handle) + 1));

    dpe_err = dpe_derive_child(invalid_handle,
                               false,  /* retain_parent_context */
                               true,   /* allow_child_to_derive */
                               false,  /* create_certificate */
                               &dice_inputs,
                               &out_child_handle,
                               &out_parent_handle);

    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveChild test: Invalid handle index should return invalid argument");
        return;
    }

    /* Use a different handle nonce */
    invalid_handle = last_retained_child_handle;
    invalid_handle = SET_NONCE(invalid_handle, (GET_NONCE(last_retained_child_handle) + 1));

    dpe_err = dpe_derive_child(invalid_handle,
                               false,  /* retain_parent_context */
                               true,   /* allow_child_to_derive */
                               false,  /* create_certificate */
                               &dice_inputs,
                               &out_child_handle,
                               &out_parent_handle);

    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveChild test: Invalid handle nonce should return invalid argument");
        return;
    }

    ret->val = TEST_PASSED;
}

void derive_child_invalid_hash_size_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int out_child_handle, out_parent_handle;
    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;

    /* Use a invalid size of measurement descriptor */
    dice_inputs.code_descriptor_size = DICE_CODE_DESCRIPTOR_MAX_SIZE + 1;

    dpe_err = dpe_derive_child(last_retained_child_handle,
                               false,  /* retain_parent_context */
                               true,   /* allow_child_to_derive */
                               false,  /* create_certificate */
                               &dice_inputs,
                               &out_child_handle,
                               &out_parent_handle);

    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveChild test: Invalid measurement descriptor size should return invalid argument");
        return;
    }

    ret->val = TEST_PASSED;
}

void derive_child_invalid_signer_id_size_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int out_child_handle, out_parent_handle;
    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;

    /* Use a invalid size of signer id descriptor */
    dice_inputs.authority_descriptor_size = DICE_AUTHORITY_DESCRIPTOR_MAX_SIZE + 1;

    dpe_err = dpe_derive_child(last_retained_child_handle,
                               false,  /* retain_parent_context */
                               true,   /* allow_child_to_derive */
                               false,  /* create_certificate */
                               &dice_inputs,
                               &out_child_handle,
                               &out_parent_handle);

    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveChild test: Invalid signer id descriptor size should return invalid argument");
        return;
    }

    ret->val = TEST_PASSED;
}

void derive_child_invalid_config_desc_size_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int out_child_handle, out_parent_handle;
    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;

    /* Use a invalid size of config descriptor */
    dice_inputs.config_descriptor_size = DICE_CONFIG_DESCRIPTOR_MAX_SIZE + 1;

    dpe_err = dpe_derive_child(last_retained_child_handle,
                               false,  /* retain_parent_context */
                               true,   /* allow_child_to_derive */
                               false,  /* create_certificate */
                               &dice_inputs,
                               &out_child_handle,
                               &out_parent_handle);

    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveChild test: Invalid config descriptor size should return invalid argument");
        return;
    }

    ret->val = TEST_PASSED;
}

void derive_child_missing_dice_input_arg_test(struct test_result_t *ret)
{
    //TODO: TO BE IMPLEMENTED

   ret->val = TEST_PASSED;
}

void derive_child_invalid_cbor_encoded_input_test(struct test_result_t *ret)
{
    //TODO: TO BE IMPLEMENTED

   ret->val = TEST_PASSED;
}

void derive_child_with_parent_leaf_component_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int out_child_handle, out_parent_handle;
    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;
    out_child_handle = INVALID_HANDLE;

    /* Call to derive_child for adding component setting it as a leaf */
    dpe_err = dpe_derive_child(last_retained_child_handle,
                               false,    /* retain_parent_context */
                               false,    /* allow_child_to_derive */
                               false,    /* create_certificate */
                               &dice_inputs,
                               &out_child_handle,
                               &out_parent_handle);

    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveChild test: Leaf component derivation failed");
        return;
    }

    if (out_child_handle != INVALID_HANDLE) {
        TEST_FAIL("DPE DeriveChild test: Should only return invalid handle for a leaf component");
    }

    /* Note: since we have used the handle with retain_parent_context
     * as false, we have created a context which cannot be destroyed
     */
    ret->val = TEST_PASSED;
}
