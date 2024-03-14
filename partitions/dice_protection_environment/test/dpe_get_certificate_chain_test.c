/*
 * Copyright (c) 2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dice_protection_environment.h"
#include "dpe_certificate_decode.h"
#include "dpe_test.h"
#include "dpe_test_data.h"

extern struct dpe_derive_context_test_data_t
              derive_context_test_dataset_1[DERIVE_CONTEXT_TEST_DATA1_SIZE];
extern int retained_rot_ctx_handle;

static void call_derive_context_with_test_data(
                        struct test_result_t *ret,
                        struct dpe_derive_context_test_data_t *test_data,
                        int test_count,
                        int *saved_handles,
                        int *saved_handles_cnt,
                        int *out_ctx_handle)
{
    dpe_error_t dpe_err;
    int in_handle, out_parent_handle;
    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;
    int i, j;

    in_handle = retained_rot_ctx_handle;

    for (i = 0; i < test_count; i++, test_data++) {

        dpe_err = dpe_derive_context(in_handle,                 /* input_ctx_handle */
                                     test_data->inputs.cert_id, /* cert_id */
                                     test_data->inputs.retain_parent_context,       /* retain_parent_context */
                                     test_data->inputs.allow_new_context_to_derive, /* allow_new_context_to_derive */
                                     test_data->inputs.create_certificate,          /* create_certificate */
                                     &dice_inputs,              /* dice_inputs */
                                     0,                         /* target_locality */
                                     false,                     /* return_certificate */
                                     true,                      /* allow_new_context_to_export */
                                     false,                     /* export_cdi */
                                     out_ctx_handle,            /* new_context_handle */
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

        if ((GET_IDX(*out_ctx_handle) == GET_IDX(out_parent_handle)) &&
            (*out_ctx_handle != INVALID_HANDLE)) {
            TEST_FAIL("DPE DeriveContext core test failed,"
                      "Derived & parent handle cannot share same component");
            return;
        }

        if (i == 0) {
            /* Save RoT context handle for subsequent tests */
            retained_rot_ctx_handle = out_parent_handle;
            TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);
        }

        if (test_data->inputs.retain_parent_context) {
            for (j = 0; j < *saved_handles_cnt; j++) {
                if(GET_IDX(out_parent_handle) ==  GET_IDX(saved_handles[j])) {
                    saved_handles[j] = out_parent_handle;
                }
            }
        }

        if (test_data->inputs.allow_new_context_to_derive) {
            saved_handles[(*saved_handles_cnt)++] = *out_ctx_handle;
        }

        /* Update the input handle for next iteration */
        if (test_data->inputs.use_parent_handle) {
            in_handle = out_parent_handle;
        } else {
            in_handle = *out_ctx_handle;
        }
    }
}

void get_certificate_chain_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int in_handle, out_ctx_handle, new_context_handle;
    int saved_handles_cnt = 0, i, err;
    uint8_t certificate_chain_buf[1650];
    size_t certificate_chain_actual_size;
    int saved_handles[MAX_NUM_OF_COMPONENTS] = {0};
    UsefulBufC cert_chain_buf;
    struct certificate_chain cert_chain = {0};

    call_derive_context_with_test_data(
            ret,
            &derive_context_test_dataset_1[0],
            sizeof(derive_context_test_dataset_1) / sizeof(derive_context_test_dataset_1[0]),
            saved_handles,
            &saved_handles_cnt,
            &out_ctx_handle);

    if (ret->val != TEST_PASSED) {
        return;
    }

    /* Use the last derived context handle for GetCertificateChain call */
    in_handle = out_ctx_handle;

    dpe_err = dpe_get_certificate_chain(in_handle,
                                        true, /* retain_context */
                                        false, /* clear_from_context */
                                        certificate_chain_buf,
                                        sizeof(certificate_chain_buf),
                                        &certificate_chain_actual_size,
                                        &new_context_handle);

    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE GetCertificateChain call failed");
        return;
    }

    /* Update renewed output handle from GetCertificateChain command */
    for (i = 0; i < saved_handles_cnt; i++) {
        if (GET_IDX(new_context_handle) == GET_IDX(saved_handles[i])) {
            saved_handles[i] = new_context_handle;
        }
    }

    cert_chain_buf = (UsefulBufC){ certificate_chain_buf,
                                   certificate_chain_actual_size };

    err = verify_certificate_chain(cert_chain_buf, &cert_chain);
    if (err) {
        TEST_FAIL("DPE certificate chain verification failed");
        return;
    }

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
