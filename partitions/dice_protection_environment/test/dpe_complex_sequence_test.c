/*
 * Copyright (c) 2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dice_protection_environment.h"
#include "dpe_certificate_decode.h"
#include "dpe_test.h"
#include "dpe_test_common.h"
#include "dpe_test_data.h"
#include "dpe_test_private.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"

#define CERT_CHAIN_SIZE 1650

extern const struct dpe_test_data_t test_data[];
/*
 *  This test will call commands in below order:
 *      DeriveContext (several times as per derive_context_test_dataset_0)
 *      GetCertificateChain
 *      CertifyKey
 *      GetCertificateChain
 *  It will test if CertifyKey request on finalised certificate context has no
 *  impact on the previously derived chain
 */
void complex_sequence_test_1(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int in_handle, new_context_handle, err;
    uint8_t certificate_chain_buf[CERT_CHAIN_SIZE];
    size_t certificate_chain_actual_size;
    UsefulBufC cert_chain_1_buf, cert_chain_2_buf;
    uint8_t pub_key[DPE_ATTEST_PUB_KEY_SIZE];
    size_t pub_key_actual_size;
    const struct dpe_test_data_t *td = &test_data[0];
    struct certificate_chain decoded_cert_chain_1 = {0};
    struct certificate_chain decoded_cert_chain_2 = {0};

    /* RoT certificate is created under "DPE_S_TEST_INIT". Now derive multiple
     * contexts as per derive_context_test_dataset_0 to create another certificate
     * and hence build up the chain.
     */
    err = build_certificate_chain(td);
    if (err) {
        TEST_FAIL("Building certificate chain based on test data failed");
        return;
    }

    /* Use the last derived context handle for GetCertificateChain call */
    in_handle = get_last_context_handle(td);

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
    update_context_handle(td, in_handle, new_context_handle);

    cert_chain_1_buf = (UsefulBufC){ certificate_chain_buf,
                                     certificate_chain_actual_size };

    /* Verify the first chain */
    err = verify_certificate_chain(cert_chain_1_buf, &decoded_cert_chain_1, NULL);
    if (err) {
        TEST_FAIL("DPE certificate chain_1 verification failed");
        return;
    }

    /* Use the last derived context handle for CertifcyKey call */
    in_handle = new_context_handle;

    /* Call CertifyKey and get leaf certificate */
    /* Note: The leaf certificate returned is not verified as the test is covered
     * under separate test case
     */
    dpe_err = dpe_certify_key(in_handle,                /* input_ctx_handle */
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
                              &new_context_handle);     /* new_context_handle */
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE CertifyKey call failed");
        return;
    }

    /* Update renewed output handle from GetCertificateChain command */
    update_context_handle(td, in_handle, new_context_handle);

    /* Use the last derived context handle for GetCertificateChain call */
    in_handle = new_context_handle;

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
    update_context_handle(td, in_handle, new_context_handle);

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
    err = destroy_multiple_context(td);
    if (err) {
        TEST_FAIL("DPE DestroyContext call failed");
        return;
    }

    ret->val = TEST_PASSED;
}
