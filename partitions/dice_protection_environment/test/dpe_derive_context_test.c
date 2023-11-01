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

extern int retained_rot_ctx_handle;

void derive_context_api_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int out_ctx_handle;
    int out_parent_handle;
    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;

    dpe_err = dpe_derive_context(retained_rot_ctx_handle,       /* input_ctx_handle */
                                 true,                          /* retain_parent_context */
                                 true,                          /* allow_new_context_to_derive */
                                 false,                         /* create_certificate */
                                 &dice_inputs,                  /* dice_inputs */
                                 0,                             /* target_locality */
                                 false,                         /* return_certificate */
                                 true,                          /* allow_new_context_to_export */
                                 false,                         /* export_cdi */
                                 &out_ctx_handle,               /* new_context_handle */
                                 &out_parent_handle,            /* new_parent_context_handle */
                                 NULL,                          /* new_certificate_buf */
                                 0,                             /* new_certificate_buf_size */
                                 NULL,                          /* new_certificate_actual_size */
                                 NULL,                          /* exported_cdi_buf */
                                 0,                             /* exported_cdi_buf_size */
                                 NULL);                         /* exported_cdi_actual_size */
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveContext call failed");
        return;
    }

    TEST_LOG("out_ctx_handle = %d\r\n", out_ctx_handle);
    TEST_LOG("out_parent_handle = %d\r\n", out_parent_handle);

    dpe_err = dpe_destroy_context(out_ctx_handle, false);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DestroyContext call failed");
        return;
    }

    /* Save the last handle for the subsequent test */
    retained_rot_ctx_handle = out_parent_handle;

    ret->val = TEST_PASSED;
}

void derive_rot_layer_context(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;
    int out_parent_handle;

    dpe_err = dpe_derive_context(ROT_CTX_HANDLE,                /* input_ctx_handle */
                                 false,                         /* retain_parent_context */
                                 true,                          /* allow_new_context_to_derive */
                                 true,                          /* create_certificate */
                                 &dice_inputs,                  /* dice_inputs */
                                 0,                             /* target_locality */
                                 false,                         /* return_certificate */
                                 true,                          /* allow_new_context_to_export */
                                 false,                         /* export_cdi */
                                 &retained_rot_ctx_handle,      /* new_context_handle */
                                 &out_parent_handle,            /* new_parent_context_handle */
                                 NULL,                          /* new_certificate_buf */
                                 0,                             /* new_certificate_buf_size */
                                 NULL,                          /* new_certificate_actual_size */
                                 NULL,                          /* exported_cdi_buf */
                                 0,                             /* exported_cdi_buf_size */
                                 NULL);                         /* exported_cdi_actual_size */
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveContext RoT context init failed");
        return;
    }

    ret->val = TEST_PASSED;
}

void derive_context_single_use_handle_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int out_ctx_handle, in_handle;
    int out_parent_handle;
    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;

    in_handle = retained_rot_ctx_handle;
    dpe_err = dpe_derive_context(in_handle,                     /* input_ctx_handle */
                                 true,                          /* retain_parent_context */
                                 true,                          /* allow_new_context_to_derive */
                                 false,                         /* create_certificate */
                                 &dice_inputs,                  /* dice_inputs */
                                 0,                             /* target_locality */
                                 false,                         /* return_certificate */
                                 true,                          /* allow_new_context_to_export */
                                 false,                         /* export_cdi */
                                 &out_ctx_handle,               /* new_context_handle */
                                 &out_parent_handle,            /* new_parent_context_handle */
                                 NULL,                          /* new_certificate_buf */
                                 0,                             /* new_certificate_buf_size */
                                 NULL,                          /* new_certificate_actual_size */
                                 NULL,                          /* exported_cdi_buf */
                                 0,                             /* exported_cdi_buf_size */
                                 NULL);                         /* exported_cdi_actual_size */
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveContext call failed");
        return;
    }

    /* Save the last handle for the subsequent test */
    retained_rot_ctx_handle = out_parent_handle;

    /* Use the previously used handle again */
    dpe_err = dpe_derive_context(in_handle,                     /* input_ctx_handle */
                                 false,                         /* retain_parent_context */
                                 true,                          /* allow_new_context_to_derive */
                                 false,                         /* create_certificate */
                                 &dice_inputs,                  /* dice_inputs */
                                 0,                             /* target_locality */
                                 false,                         /* return_certificate */
                                 true,                          /* allow_new_context_to_export */
                                 false,                         /* export_cdi */
                                 &out_ctx_handle,               /* new_context_handle */
                                 &out_parent_handle,            /* new_parent_context_handle */
                                 NULL,                          /* new_certificate_buf */
                                 0,                             /* new_certificate_buf_size */
                                 NULL,                          /* new_certificate_actual_size */
                                 NULL,                          /* exported_cdi_buf */
                                 0,                             /* exported_cdi_buf_size */
                                 NULL);                         /* exported_cdi_actual_size */

    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveContext test: Same handle used again should return invalid argument");
        return;
    }

    dpe_err = dpe_destroy_context(out_ctx_handle, false);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DestroyContext call failed");
        return;
    }

    ret->val = TEST_PASSED;
}
void derive_context_incorrect_handle_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int out_ctx_handle, out_parent_handle, invalid_handle;
    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;

    /* Use a different handle index */
    invalid_handle = retained_rot_ctx_handle;
    invalid_handle = SET_IDX(invalid_handle, (GET_IDX(retained_rot_ctx_handle) + 1));

    dpe_err = dpe_derive_context(invalid_handle,                /* input_ctx_handle */
                                 false,                         /* retain_parent_context */
                                 true,                          /* allow_new_context_to_derive */
                                 false,                         /* create_certificate */
                                 &dice_inputs,                  /* dice_inputs */
                                 0,                             /* target_locality */
                                 false,                         /* return_certificate */
                                 true,                          /* allow_new_context_to_export */
                                 false,                         /* export_cdi */
                                 &out_ctx_handle,               /* new_context_handle */
                                 &out_parent_handle,            /* new_parent_context_handle */
                                 NULL,                          /* new_certificate_buf */
                                 0,                             /* new_certificate_buf_size */
                                 NULL,                          /* new_certificate_actual_size */
                                 NULL,                          /* exported_cdi_buf */
                                 0,                             /* exported_cdi_buf_size */
                                 NULL);                         /* exported_cdi_actual_size */

    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveContext test: Invalid handle index should return invalid argument");
        return;
    }

    /* Use a different handle nonce */
    invalid_handle = retained_rot_ctx_handle;
    invalid_handle = SET_NONCE(invalid_handle, (GET_NONCE(retained_rot_ctx_handle) + 1));

    dpe_err = dpe_derive_context(invalid_handle,                /* input_ctx_handle */
                                 false,                         /* retain_parent_context */
                                 true,                          /* allow_new_context_to_derive */
                                 false,                         /* create_certificate */
                                 &dice_inputs,                  /* dice_inputs */
                                 0,                             /* target_locality */
                                 false,                         /* return_certificate */
                                 true,                          /* allow_new_context_to_export */
                                 false,                         /* export_cdi */
                                 &out_ctx_handle,               /* new_context_handle */
                                 &out_parent_handle,            /* new_parent_context_handle */
                                 NULL,                          /* new_certificate_buf */
                                 0,                             /* new_certificate_buf_size */
                                 NULL,                          /* new_certificate_actual_size */
                                 NULL,                          /* exported_cdi_buf */
                                 0,                             /* exported_cdi_buf_size */
                                 NULL);                         /* exported_cdi_actual_size */

    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveContext test: Invalid handle nonce should return invalid argument");
        return;
    }

    ret->val = TEST_PASSED;
}

void derive_context_invalid_hash_size_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int out_ctx_handle, out_parent_handle;
    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;

    /* Use a invalid size of measurement descriptor */
    dice_inputs.code_descriptor_size = DICE_CODE_DESCRIPTOR_MAX_SIZE + 1;

    dpe_err = dpe_derive_context(retained_rot_ctx_handle,       /* input_ctx_handle */
                                 false,                         /* retain_parent_context */
                                 true,                          /* allow_new_context_to_derive */
                                 false,                         /* create_certificate */
                                 &dice_inputs,                  /* dice_inputs */
                                 0,                             /* target_locality */
                                 false,                         /* return_certificate */
                                 true,                          /* allow_new_context_to_export */
                                 false,                         /* export_cdi */
                                 &out_ctx_handle,               /* new_context_handle */
                                 &out_parent_handle,            /* new_parent_context_handle */
                                 NULL,                          /* new_certificate_buf */
                                 0,                             /* new_certificate_buf_size */
                                 NULL,                          /* new_certificate_actual_size */
                                 NULL,                          /* exported_cdi_buf */
                                 0,                             /* exported_cdi_buf_size */
                                 NULL);                         /* exported_cdi_actual_size */

    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveContext test: Invalid measurement descriptor size should return invalid argument");
        return;
    }

    ret->val = TEST_PASSED;
}

void derive_context_invalid_signer_id_size_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int out_ctx_handle, out_parent_handle;
    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;

    /* Use a invalid size of signer id descriptor */
    dice_inputs.authority_descriptor_size = DICE_AUTHORITY_DESCRIPTOR_MAX_SIZE + 1;

    dpe_err = dpe_derive_context(retained_rot_ctx_handle,       /* input_ctx_handle */
                                 false,                         /* retain_parent_context */
                                 true,                          /* allow_new_context_to_derive */
                                 false,                         /* create_certificate */
                                 &dice_inputs,                  /* dice_inputs */
                                 0,                             /* target_locality */
                                 false,                         /* return_certificate */
                                 true,                          /* allow_new_context_to_export */
                                 false,                         /* export_cdi */
                                 &out_ctx_handle,               /* new_context_handle */
                                 &out_parent_handle,            /* new_parent_context_handle */
                                 NULL,                          /* new_certificate_buf */
                                 0,                             /* new_certificate_buf_size */
                                 NULL,                          /* new_certificate_actual_size */
                                 NULL,                          /* exported_cdi_buf */
                                 0,                             /* exported_cdi_buf_size */
                                 NULL);                         /* exported_cdi_actual_size */

    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveContext test: Invalid signer id descriptor size should return invalid argument");
        return;
    }

    ret->val = TEST_PASSED;
}

void derive_context_invalid_config_desc_size_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int out_ctx_handle, out_parent_handle;
    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;

    /* Use a invalid size of config descriptor */
    dice_inputs.config_descriptor_size = DICE_CONFIG_DESCRIPTOR_MAX_SIZE + 1;

    dpe_err = dpe_derive_context(retained_rot_ctx_handle,       /* input_ctx_handle */
                                 false,                         /* retain_parent_context */
                                 true,                          /* allow_new_context_to_derive */
                                 false,                         /* create_certificate */
                                 &dice_inputs,                  /* dice_inputs */
                                 0,                             /* target_locality */
                                 false,                         /* return_certificate */
                                 true,                          /* allow_new_context_to_export */
                                 false,                         /* export_cdi */
                                 &out_ctx_handle,               /* new_context_handle */
                                 &out_parent_handle,            /* new_parent_context_handle */
                                 NULL,                          /* new_certificate_buf */
                                 0,                             /* new_certificate_buf_size */
                                 NULL,                          /* new_certificate_actual_size */
                                 NULL,                          /* exported_cdi_buf */
                                 0,                             /* exported_cdi_buf_size */
                                 NULL);                         /* exported_cdi_actual_size */

    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveContext test: Invalid config descriptor size should return invalid argument");
        return;
    }

    ret->val = TEST_PASSED;
}

void derive_context_missing_dice_input_arg_test(struct test_result_t *ret)
{
    //TODO: TO BE IMPLEMENTED

   ret->val = TEST_PASSED;
}

void derive_context_invalid_cbor_encoded_input_test(struct test_result_t *ret)
{
    //TODO: TO BE IMPLEMENTED

   ret->val = TEST_PASSED;
}

void derive_context_smaller_cert_buffer_test(struct test_result_t *ret)
{
    //TODO: TO BE IMPLEMENTED

   ret->val = TEST_PASSED;
}

void derive_context_smaller_cdi_buffer_test(struct test_result_t *ret)
{
    //TODO: TO BE IMPLEMENTED

   ret->val = TEST_PASSED;
}
void derive_context_prevent_cdi_export_test(struct test_result_t *ret)
{
    //TODO: TO BE IMPLEMENTED

   ret->val = TEST_PASSED;
}
void derive_context_invalid_input_param_combination_test(struct test_result_t *ret)
{
    //TODO: TO BE IMPLEMENTED

   ret->val = TEST_PASSED;
}
void derive_context_missing_req_input_param_combination_test(struct test_result_t *ret)
{
    //TODO: TO BE IMPLEMENTED

   ret->val = TEST_PASSED;
}
void derive_context_check_export_cdi_test(struct test_result_t *ret)
{
    //TODO: TO BE IMPLEMENTED

   ret->val = TEST_PASSED;
}

void derive_context_with_parent_leaf_component_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int out_ctx_handle, out_parent_handle;
    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;
    out_ctx_handle = INVALID_HANDLE;

    /* Call to derive_context for adding component setting it as a leaf */
    dpe_err = dpe_derive_context(retained_rot_ctx_handle,       /* input_ctx_handle */
                                 false,                         /* retain_parent_context */
                                 false,                         /* allow_new_context_to_derive */
                                 false,                         /* create_certificate */
                                 &dice_inputs,                  /* dice_inputs */
                                 0,                             /* target_locality */
                                 false,                         /* return_certificate */
                                 true,                          /* allow_new_context_to_export */
                                 false,                         /* export_cdi */
                                 &out_ctx_handle,               /* new_context_handle */
                                 &out_parent_handle,            /* new_parent_context_handle */
                                 NULL,                          /* new_certificate_buf */
                                 0,                             /* new_certificate_buf_size */
                                 NULL,                          /* new_certificate_actual_size */
                                 NULL,                          /* exported_cdi_buf */
                                 0,                             /* exported_cdi_buf_size */
                                 NULL);                         /* exported_cdi_actual_size */

    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveContext test: Leaf component derivation failed");
        return;
    }

    if (out_ctx_handle != INVALID_HANDLE) {
        TEST_FAIL("DPE DeriveContext test: Should only return invalid handle for a leaf component");
    }

    /* Note: since we have used the handle with allow_new_context_to_derive
     * as false, we have created a context which cannot be destroyed
     */
    ret->val = TEST_PASSED;
}
