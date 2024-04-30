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
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"

#define CERT_CHAIN_SIZE 1650

extern struct dpe_derive_context_test_data_t
              derive_context_test_dataset_1[DERIVE_CONTEXT_TEST_DATA1_SIZE];

/*
 *  This test will call commands in below order:
 *      DeriveContext (several times as per derive_context_test_dataset_1)
 *      GetCertificateChain
 *      CertifyKey
 *      GetCertificateChain
 *  It will test if CertifyKey request on finalised layer has no impact on the
 *  previously derived chain
 */
void complex_sequence_test_1(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int in_handle, out_ctx_handle, new_context_handle, err;
    int saved_handles_cnt = 0, i, last_handle_idx, last_handle;
    uint8_t certificate_chain_buf[CERT_CHAIN_SIZE];
    size_t certificate_chain_actual_size;
    int saved_handles[MAX_NUM_OF_COMPONENTS] = {0};
    UsefulBufC cert_chain_1_buf, cert_chain_2_buf;
    uint8_t pub_key[DPE_ATTEST_PUB_KEY_SIZE];
    size_t pub_key_actual_size;
    struct certificate_chain decoded_cert_chain_1 = {0};
    struct certificate_chain decoded_cert_chain_2 = {0};

    /* RoT certificate is created under "DPE_S_TEST_INIT". Now derive multiple
     * contexts as per derive_context_test_dataset_1 to create another certificate
     * and hence build up the chain
     */
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

    cert_chain_1_buf = (UsefulBufC){ certificate_chain_buf,
                                     certificate_chain_actual_size };

    /* Verify the first chain */
    err = verify_certificate_chain(cert_chain_1_buf, &decoded_cert_chain_1, NULL);
    if (err) {
        TEST_FAIL("DPE certificate chain_1 verification failed");
        return;
    }

    last_handle_idx = saved_handles_cnt - 1;
    last_handle = saved_handles[last_handle_idx];

    /* Call CertifyKey and get leaf certificate */
    /* Note: The leaf certificate returned is not verified as the test is covered
     * under separate test case
     */
    dpe_err = dpe_certify_key(last_handle,              /* input_ctx_handle */
                              true,                     /* retain_context/ */
                              NULL,                     /* public_key */
                              0,                        /* public_key_size */
                              NULL,                     /* label */
                              0,                        /* label_size */
                              certificate_chain_buf,    /* certificate_chain_buf */
                              sizeof(certificate_chain_buf), /* certificate_chain_buf_size */
                              &certificate_chain_actual_size, /* certificate_chain_actual_size */
                              pub_key,                  /* derived_public_key_buf */
                              sizeof(pub_key),          /* derived_public_key_buf_size */
                              &pub_key_actual_size,     /* derived_public_key_buf_actual_size */
                              &saved_handles[last_handle_idx]);     /* new_context_handle */
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE CertifyKey call failed");
        return;
    }

    /* Use the last derived context handle for GetCertificateChain call */
    in_handle = saved_handles[last_handle_idx];
    dpe_err = dpe_get_certificate_chain(in_handle,
                                        true, /* retain_context */
                                        false, /* clear_from_context */
                                        certificate_chain_buf,
                                        sizeof(certificate_chain_buf),
                                        &certificate_chain_actual_size,
                                        &saved_handles[last_handle_idx]);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE GetCertificateChain call failed");
        return;
    }

    cert_chain_2_buf = (UsefulBufC){ certificate_chain_buf,
                                     certificate_chain_actual_size };

    /* Verify the second chain */
    err = verify_certificate_chain(cert_chain_2_buf, &decoded_cert_chain_2, NULL);
    if (err) {
        TEST_FAIL("DPE certificate chain_2 verification failed");
        return;
    }

    /* Compare the two chains */
    err = compare_certificate_chains(&decoded_cert_chain_1, &decoded_cert_chain_2);
    if (err) {
        TEST_FAIL("DPE certificate chain_1 and chain_2 comparison failed");
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
