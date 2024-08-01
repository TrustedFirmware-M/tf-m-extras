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

extern const struct dpe_test_data_t test_data[];

void get_certificate_chain_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int in_handle, new_context_handle;
    int err;
    uint8_t certificate_chain_buf[1650];
    size_t certificate_chain_actual_size;
    UsefulBufC cert_chain_buf;
    struct certificate_chain cert_chain = {0};
    const struct dpe_test_data_t *td = &test_data[0];

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

    cert_chain_buf = (UsefulBufC){ certificate_chain_buf,
                                   certificate_chain_actual_size };

    err = verify_certificate_chain(cert_chain_buf, &cert_chain, NULL);
    if (err) {
        TEST_FAIL("DPE certificate chain verification failed");
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

void
get_certificate_chain_mixing_cert_id_multiple_ctx_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int in_handle, new_context_handle;
    int err;
    uint8_t certificate_chain_buf[1650];
    size_t certificate_chain_actual_size;
    UsefulBufC cert_chain_buf;
    struct certificate_chain cert_chain = {0};
    const struct dpe_test_data_t *td = &test_data[2];

    err = build_certificate_chain(td);
    if (err) {
        TEST_FAIL("Building certificate chain based on test data failed");
        return;
    }

    /* Use the last derived context handle for GetCertificateChain call */
    in_handle = get_last_context_handle(td);

    dpe_err = dpe_get_certificate_chain(in_handle,
                                        true,  /* retain_context */
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

    cert_chain_buf = (UsefulBufC){ certificate_chain_buf,
                                   certificate_chain_actual_size };

    err = verify_certificate_chain(cert_chain_buf, &cert_chain, NULL);
    if (err) {
        TEST_FAIL("DPE certificate chain verification failed");
        return;
    }

    err = destroy_multiple_context(td);
    if (err) {
        TEST_FAIL("DPE destroying multiple context failed");
        return;
    }

    ret->val = TEST_PASSED;
}
