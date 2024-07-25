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
#include "dpe_test_private.h"

extern struct dpe_derive_context_test_data_t
              derive_context_test_dataset_1[DERIVE_CONTEXT_TEST_DATA1_SIZE];
extern struct dpe_derive_context_test_data_t
              derive_context_test_dataset_3[DERIVE_CONTEXT_TEST_DATA3_SIZE];

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

    err = verify_certificate_chain(cert_chain_buf, &cert_chain, NULL);
    if (err) {
        TEST_FAIL("DPE certificate chain verification failed");
        return;
    }

    /* Destroy the saved contexts for the subsequent test */
    for (i = 0; i < saved_handles_cnt; i++) {
        DESTROY_SINGLE_CONTEXT(saved_handles[i]);
    }

    ret->val = TEST_PASSED;
}

void
get_certificate_chain_mixing_cert_id_multiple_ctx_test(struct test_result_t *ret)
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
            &derive_context_test_dataset_3[0],
            sizeof(derive_context_test_dataset_3) / sizeof(derive_context_test_dataset_3[0]),
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

    err = verify_certificate_chain(cert_chain_buf, &cert_chain, NULL);
    if (err) {
        TEST_FAIL("DPE certificate chain verification failed");
        return;
    }

    /* Destroy the saved contexts for the subsequent test */
    for (i = saved_handles_cnt - 1; i >= 0; i--) {
        DESTROY_SINGLE_CONTEXT(saved_handles[i]);
    }

    ret->val = TEST_PASSED;
}
