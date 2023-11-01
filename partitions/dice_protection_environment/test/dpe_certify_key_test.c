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

extern struct dpe_derive_context_test_data_t
              derive_context_test_dataset_1[DERIVE_CONTEXT_TEST_DATA1_SIZE];
extern struct dpe_derive_context_test_data_t
              derive_context_test_dataset_2;
extern int retained_rot_ctx_handle;

static void call_certify_key_with_test_data(
                        struct test_result_t *ret,
                        struct dpe_derive_context_test_data_t *test_data,
                        int test_count)
{
    dpe_error_t dpe_err;
    int in_handle, out_ctx_handle, out_parent_handle, new_context_handle;
    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;
    int saved_handles_cnt, i, j;
    uint8_t certificate_chain_buf[3072];
    size_t certificate_chain_actual_size;
    uint8_t derived_public_key_buf[DPE_ATTEST_PUB_KEY_SIZE];
    size_t derived_public_key_actual_size;
    int saved_handles[MAX_NUM_OF_COMPONENTS] = {0};

    saved_handles_cnt = 0;
    in_handle = retained_rot_ctx_handle;

    for (i = 0; i < test_count; i++, test_data++) {

        dpe_err = dpe_derive_context(in_handle,                 /* input_ctx_handle */
                                     test_data->inputs.retain_parent_context,       /* retain_parent_context */
                                     test_data->inputs.allow_new_context_to_derive, /* allow_new_context_to_derive */
                                     test_data->inputs.create_certificate,          /* create_certificate */
                                     &dice_inputs,              /* dice_inputs */
                                     0,                         /* target_locality */
                                     false,                     /* return_certificate */
                                     true,                      /* allow_new_context_to_export */
                                     false,                     /* export_cdi */
                                     &out_ctx_handle,           /* new_context_handle */
                                     &out_parent_handle,        /* new_parent_context_handle */
                                     NULL,                      /* new_certificate_buf */
                                     0,                         /* new_certificate_buf_size */
                                     NULL,                      /* new_certificate_actual_size */
                                     NULL,                      /* exported_cdi_buf */
                                     0,                         /* exported_cdi_buf_size */
                                     NULL);                     /* exported_cdi_actual_size */

        if (dpe_err != DPE_NO_ERROR) {
            TEST_FAIL("DPE DeriveContext core functionality test failed");
            return;
        }

        if ((GET_IDX(out_ctx_handle) == GET_IDX(out_parent_handle)) &&
            (out_ctx_handle != INVALID_HANDLE)) {
            TEST_FAIL("DPE DeriveContext core test failed,"
                      "Derived & parent handle cannot share same component");
            return;
        }

        if (i == 0) {
            /* Save RoT context handle for subsequent tests */
            retained_rot_ctx_handle = out_parent_handle;
        }

        if (test_data->inputs.retain_parent_context) {
            for (j = 0; j < saved_handles_cnt; j++) {
                if(GET_IDX(out_parent_handle) ==  GET_IDX(saved_handles[j])) {
                    saved_handles[j] = out_parent_handle;
                }
            }
        }

        if (test_data->inputs.allow_new_context_to_derive) {
            saved_handles[saved_handles_cnt++] = out_ctx_handle;
        }

        /* Update the input handle for next iteration */
        if (test_data->inputs.use_parent_handle) {
            in_handle = out_parent_handle;
        } else {
            in_handle = out_ctx_handle;
        }
    }

    /* Use the last derived context handle for CertifyKey call */
    in_handle = out_ctx_handle;

    dpe_err = dpe_certify_key(in_handle,                        /* input_ctx_handle */
                              true,                             /* retain_context/ */
                              NULL,                             /* public_key */
                              0,                                /* public_key_size */
                              NULL,                             /* label */
                              0,                                /* label_size */
                              certificate_chain_buf,            /* certificate_chain_buf */
                              sizeof(certificate_chain_buf),    /* certificate_chain_buf_size */
                              &certificate_chain_actual_size,   /* certificate_chain_buf_actual_size */
                              derived_public_key_buf,           /* derived_public_key_buf */
                              sizeof(derived_public_key_buf),   /* derived_public_key_buf_size */
                              &derived_public_key_actual_size,  /* derived_public_key_buf_actual_size */
                              &new_context_handle);             /* new_context_handle */
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE CertifyKey call failed");
        return;
    }

    if (derived_public_key_actual_size > DPE_ATTEST_PUB_KEY_SIZE) {
        TEST_FAIL("DPE CertifyKey test: Derived public key size greater than expected");
        return;
    }

    /* Update renewed output handle from CertifyKey command */
    for (i = 0; i < saved_handles_cnt; i++) {
        if (GET_IDX(new_context_handle) == GET_IDX(saved_handles[i])) {
            saved_handles[i] = new_context_handle;
        }
    }

    //TODO: Verify the output certificate chain

    /* Destroy the saved contexts for the subsequent test */
    for (i = 0; i < saved_handles_cnt; i++) {
        dpe_err = dpe_destroy_context(saved_handles[i], false);
        if (dpe_err != DPE_NO_ERROR) {
            TEST_FAIL("DPE DestroyContext call failed");
            return;
        }
    }

    ret->val = TEST_PASSED;
}

void certify_key_core_functionality_test(struct test_result_t *ret)
{
    call_certify_key_with_test_data(
            ret,
            &derive_context_test_dataset_1[0],
            sizeof(derive_context_test_dataset_1)/sizeof(derive_context_test_dataset_1[0]));

    call_certify_key_with_test_data(
            ret,
            &derive_context_test_dataset_2,
            DERIVE_CONTEXT_TEST_DATA2_SIZE);
}

void certify_key_api_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int out_ctx_handle;
    const uint8_t label[] = { 0x1A, 0xBE, 0x1 };
    uint8_t certificate_chain_buf[2000];
    size_t certificate_chain_actual_size;
    uint8_t derived_public_key_buf[DPE_ATTEST_PUB_KEY_SIZE];
    size_t derived_public_key_actual_size;
    int new_context_handle;
    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;
    int out_parent_handle;

    dpe_err = dpe_derive_context(retained_rot_ctx_handle,       /* input_ctx_handle */
                                 true,                          /* retain_parent_context */
                                 true,                          /* allow_new_context_to_derive */
                                 true,                          /* create_certificate */
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

    dpe_err = dpe_certify_key(out_ctx_handle,                   /* input_ctx_handle */
                              true,                             /* retain_context */
                              NULL,                             /* public_key */
                              0,                                /* public_key_size */
                              label,                            /* label */
                              sizeof(label),                    /* label_size */
                              certificate_chain_buf,            /* certificate_chain_buf */
                              sizeof(certificate_chain_buf),    /* certificate_chain_buf_size */
                              &certificate_chain_actual_size,   /* certificate_chain_buf_actual_size */
                              derived_public_key_buf,           /* derived_public_key_buf */
                              sizeof(derived_public_key_buf),   /* derived_public_key_buf_size */
                              &derived_public_key_actual_size,  /* derived_public_key_buf_actual_size */
                              &new_context_handle);             /* new_context_handle */
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE CertifyKey call failed");
        return;
    }

    dpe_err = dpe_destroy_context(new_context_handle, false);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DestroyContext call failed");
        return;
    }

    /* Save the last handle for the subsequent test */
    retained_rot_ctx_handle = out_parent_handle;

    ret->val = TEST_PASSED;
}

void certify_key_retain_context_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int out_ctx_handle;
    const uint8_t label[] = { 0x1A, 0xBE, 0x1 };
    uint8_t certificate_chain_buf[2000];
    size_t certificate_chain_actual_size;
    uint8_t derived_public_key_buf[DPE_ATTEST_PUB_KEY_SIZE];
    size_t derived_public_key_actual_size;
    int new_context_handle;
    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;
    int out_parent_handle;

    dpe_err = dpe_derive_context(retained_rot_ctx_handle,       /* context_handle */
                                 true,                          /* retain_parent_context */
                                 true,                          /* allow_new_context_to_derive */
                                 true,                          /* create_certificate */
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

    dpe_err = dpe_certify_key(out_ctx_handle,                   /* input_ctx_handle */
                              false,                            /* retain_context */
                              NULL,                             /* public_key */
                              0,                                /* public_key_size */
                              label,                            /* label */
                              sizeof(label),                    /* label_size */
                              certificate_chain_buf,            /* certificate_chain_buf */
                              sizeof(certificate_chain_buf),    /* certificate_chain_buf_size */
                              &certificate_chain_actual_size,   /* certificate_chain_buf_actual_size */
                              derived_public_key_buf,           /* derived_public_key_buf */
                              sizeof(derived_public_key_buf),   /* derived_public_key_buf_size */
                              &derived_public_key_actual_size,  /* derived_public_key_buf_actual_size */
                              &new_context_handle);             /* new_context_handle */
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE CertifyKey call failed");
        return;
    }

    if (new_context_handle != INVALID_HANDLE) {
        TEST_FAIL("DPE CertifyKey should return invalid handle when input arg "
                  "retain_context is false");
        (void)dpe_destroy_context(new_context_handle, false);
        return;
    }

    /* Destroy other derived contexts for subsequent test */
    dpe_err = dpe_destroy_context(new_context_handle, false);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DestroyContext call failed");
        return;
    }
    ret->val = TEST_PASSED;
}

void certify_key_incorrect_handle_test(struct test_result_t *ret)
{
    //TODO: TO BE IMPLEMENTED

   ret->val = TEST_PASSED;
}

void certify_key_supplied_pub_key_test(struct test_result_t *ret)
{
    //TODO: TO BE IMPLEMENTED

   ret->val = TEST_PASSED;
}

void certify_key_supplied_label_test(struct test_result_t *ret)
{
    //TODO: TO BE IMPLEMENTED

   ret->val = TEST_PASSED;
}

void certify_key_smaller_cert_buffer_test(struct test_result_t *ret)
{
    //TODO: TO BE IMPLEMENTED

   ret->val = TEST_PASSED;
}

void certify_key_smaller_derived_pub_key_buffer_test(struct test_result_t *ret)
{
    //TODO: TO BE IMPLEMENTED

   ret->val = TEST_PASSED;
}

void certify_key_invalid_cbor_encoded_input_test(struct test_result_t *ret)
{
    //TODO: TO BE IMPLEMENTED

   ret->val = TEST_PASSED;
}
