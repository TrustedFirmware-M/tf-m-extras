/*
 * Copyright (c) 2023-2025, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <string.h>
#include "dice_protection_environment.h"
#include "dpe_certificate_decode.h"
#include "dpe_test.h"
#include "dpe_test_common.h"
#include "dpe_test_data.h"
#include "dpe_test_private.h"
#include "t_cose/t_cose_key.h"

extern const struct dpe_test_data_t test_data[];
extern int retained_rot_ctx_handle;

static int get_and_verify_certificate_chain(int in_handle,
                                            struct t_cose_key *pub_key_id,
                                            int *out_ctx_handle)
{
    uint8_t certificate_buf[1650];
    size_t certificate_actual_size;
    UsefulBufC cert_chain_buf;
    dpe_error_t dpe_err;
    struct certificate_chain cert_chain = {0};
    int err;

    dpe_err = dpe_get_certificate_chain(in_handle,
                                        true, /* retain_context */
                                        false, /* clear_from_context */
                                        certificate_buf,
                                        sizeof(certificate_buf),
                                        &certificate_actual_size,
                                        out_ctx_handle);

    if (dpe_err != DPE_NO_ERROR) {
        TEST_LOG("DPE GetCertificateChain call failed");
        return -1;
    }
    cert_chain_buf = (UsefulBufC){ certificate_buf,
                                   certificate_actual_size };

    err = verify_certificate_chain(cert_chain_buf, &cert_chain, pub_key_id);
    if (err) {
        TEST_LOG("DPE certificate chain verification failed");
        return -1;
    }
}

static int get_and_verify_leaf_certificate(int in_handle,
                                           struct t_cose_key pub_key_id,
                                           int *out_ctx_handle)
{
    UsefulBufC cert_buf;
    int err;
    dpe_error_t dpe_err;
    struct certificate cert = {0};
    struct certify_key_cmd_input_t ck_input = DEFAULT_CK_CMD_INPUT;
    struct certify_key_cmd_output_t ck_output = {0};

    ADD_CERT_CHAIN_BUF(ck_output, 1650);
    ADD_DERIVED_PUB_KEY_BUF(ck_output, DPE_ATTEST_PUB_KEY_SIZE);

    ck_input.context_handle = in_handle;

    dpe_err = CALL_CERTIFY_KEY(ck_input, ck_output);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_LOG("DPE CertifyKey call failed");
        return -1;
    }

    if (ck_output.derived_public_key_actual_size > DPE_ATTEST_PUB_KEY_SIZE) {
        TEST_LOG("DPE CertifyKey test: Derived public key size greater than expected");
        return -1;
    }

    /* Return the next valid context_handle */
    *out_ctx_handle = ck_output.new_context_handle;

    cert_buf = (UsefulBufC){ ck_output.certificate_chain_buf,
                             ck_output.certificate_chain_actual_size };
    err = verify_certificate(cert_buf, pub_key_id, &cert);
    if (err) {
        TEST_LOG("DPE certificate chain verification failed");
        return -1;
    }

    err = unregister_pub_key(pub_key_id);
    if (err) {
        TEST_LOG("DPE public key unregistration failed");
        return -1;
    }
}

/*
 * Test with finalized certificate context:
 *   - Build up the certificate chain based on derive_context_test_dataset_0.
 *   - Query the certificate chain and verify it. Get a reference to the
 *     public key in the last certificate.
 *   - Send a CertifyKey command to get a leaf certificate and verify it
 *     with the held reference to the public key coming from the last
 *     certificate.
 */
void certify_key_core_functionality_test_01(struct test_result_t *ret)
{
    struct t_cose_key pub_key_id;
    int err, in_handle, out_ctx_handle;
    const struct dpe_test_data_t *td = &test_data[0];

    err = build_certificate_chain(td);
    if (err) {
        TEST_FAIL("Building certificate chain based on test data failed");
        return;
    }

    /* Use the last derived context handle */
    in_handle = get_last_context_handle(td);

    err = get_and_verify_certificate_chain(in_handle,
                                           &pub_key_id,
                                           &out_ctx_handle);
    if (err) {
        TEST_FAIL("Get and verify certificate chain falied");
        return;
    }

    update_context_handle(td, in_handle, out_ctx_handle);

    in_handle = out_ctx_handle;
    err = get_and_verify_leaf_certificate(in_handle,
                                          pub_key_id,
                                          &out_ctx_handle);
    if (err) {
        TEST_FAIL("Get and verify leaf certificate falied");
        return;
    }

    update_context_handle(td, in_handle, out_ctx_handle);

    /* Destroy the saved contexts for the subsequent test */
    err = destroy_multiple_context(td);
    if (err) {
        TEST_FAIL("DPE DestroyContext call failed");
        return;
    }

    ret->val = TEST_PASSED;
}

/*
 * Test with unfinished certificate context:
 *   - Query the certificate chain, contains only the RoT certificate, and
 *     verify it. Get a reference to the public key in the last certificate.
 *   - Build up the certificate chain based on derive_context_test_dataset_1.
 *   - Send a CertifyKey command to get a leaf certificate and verify it
 *     with the held reference to the public key coming from the last
 *     certificate.
 */
void certify_key_core_functionality_test_02(struct test_result_t *ret)
{
    struct t_cose_key pub_key_id;
    int err, in_handle, out_ctx_handle;
    const struct dpe_test_data_t *td = &test_data[1];

    in_handle = retained_rot_ctx_handle;
    err = get_and_verify_certificate_chain(in_handle,
                                           &pub_key_id,
                                           &out_ctx_handle);
    if (err) {
        TEST_FAIL("Get and verify certificate chain falied");
        return;
    }

    retained_rot_ctx_handle = out_ctx_handle;
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);

    err = build_certificate_chain(td);
    if (err) {
        TEST_FAIL("Building certificate chain based on test data failed");
        return;
    }

    /* Use the last derived context handle */
    in_handle = get_last_context_handle(td);

    err = get_and_verify_leaf_certificate(in_handle,
                                          pub_key_id,
                                          &out_ctx_handle);
    if (err) {
        TEST_FAIL("Get and verify leaf certificate falied");
        return;
    }

    update_context_handle(td, in_handle, out_ctx_handle);

    /* Destroy the saved contexts for the subsequent test */
    err = destroy_multiple_context(td);
    if (err) {
        TEST_FAIL("DPE DestroyContext call failed");
        return;
    }

    ret->val = TEST_PASSED;
}

void certify_key_api_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    struct derive_context_cmd_input_t dc_input = DEFAULT_DC_CMD_INPUT;
    struct derive_context_cmd_output_t dc_output = {0};
    uint8_t label[] = { 0x1A, 0xBE, 0x1 };
    struct certify_key_cmd_input_t ck_input = DEFAULT_CK_CMD_INPUT;
    struct certify_key_cmd_output_t ck_output = {0};

    ADD_CERT_CHAIN_BUF(ck_output, 2000);
    ADD_DERIVED_PUB_KEY_BUF(ck_output, DPE_ATTEST_PUB_KEY_SIZE);

    dc_input.context_handle = retained_rot_ctx_handle;
    dc_input.create_certificate = true;

    dpe_err = CALL_DERIVE_CONTEXT(dc_input, dc_output);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveContext call failed");
        return;
    }
    ck_input.context_handle = dc_output.out_ctx_handle;
    ck_input.label = label;
    ck_input.label_size = sizeof(label);

    dpe_err = CALL_CERTIFY_KEY(ck_input, ck_output);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE CertifyKey call failed");
        return;
    }

    DESTROY_SINGLE_CONTEXT(ck_output.new_context_handle);

    /* Save the last handle for the subsequent test */
    retained_rot_ctx_handle = dc_output.out_parent_handle;
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);

    ret->val = TEST_PASSED;
}

void certify_key_retain_context_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    struct derive_context_cmd_input_t dc_input = DEFAULT_DC_CMD_INPUT;
    struct derive_context_cmd_output_t dc_output = {0};
    struct certify_key_cmd_input_t ck_input = DEFAULT_CK_CMD_INPUT;
    struct certify_key_cmd_output_t ck_output = {0};

    ADD_CERT_CHAIN_BUF(ck_output, 1300);
    ADD_DERIVED_PUB_KEY_BUF(ck_output, DPE_ATTEST_PUB_KEY_SIZE);

    dc_input.context_handle = retained_rot_ctx_handle;
    dc_input.create_certificate = true;
    dc_input.cert_id = DPE_UNDESTROYABLE_CTX_CERT_ID_3;

    dpe_err = CALL_DERIVE_CONTEXT(dc_input, dc_output);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveContext call failed");
        return;
    }

    /* Save the last handle for the subsequent test */
    retained_rot_ctx_handle = dc_output.out_parent_handle;
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);

    ck_input.context_handle = dc_output.out_ctx_handle;
    ck_input.retain_context = false;

    dpe_err = CALL_CERTIFY_KEY(ck_input, ck_output);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE CertifyKey call failed");
        return;
    }

    if (ck_output.new_context_handle != INVALID_HANDLE) {
        TEST_FAIL("DPE CertifyKey should return invalid handle when input arg "
                  "retain_context is false");
        DESTROY_SINGLE_CONTEXT(ck_output.new_context_handle);
        return;
    }

    /* Since retain_context is false, it will create undestroyable context */
    ret->val = TEST_PASSED;
}

void certify_key_incorrect_handle_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    struct derive_context_cmd_input_t dc_input = DEFAULT_DC_CMD_INPUT;
    struct derive_context_cmd_output_t dc_output = {0};
    struct certify_key_cmd_input_t ck_input = DEFAULT_CK_CMD_INPUT;
    struct certify_key_cmd_output_t ck_output = {0};
    ADD_CERT_CHAIN_BUF(ck_output, 10);

    dc_input.context_handle = retained_rot_ctx_handle;
    dc_input.create_certificate = true;

    dpe_err = CALL_DERIVE_CONTEXT(dc_input, dc_output);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveContext call failed");
        return;
    }

    /* Use incorrect handle */
    ck_input.context_handle = dc_output.out_ctx_handle + 1;

    dpe_err = CALL_CERTIFY_KEY(ck_input, ck_output);
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE CertifyKey test: Invalid handle nonce should return invalid argument");
        return;
    }

    /* Destroy other derived contexts for subsequent test */
    DESTROY_SINGLE_CONTEXT(dc_output.out_ctx_handle);

    /* Save the last handle for the subsequent test */
    retained_rot_ctx_handle = dc_output.out_parent_handle;
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);

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
    dpe_error_t dpe_err;
    struct derive_context_cmd_input_t dc_input = DEFAULT_DC_CMD_INPUT;
    struct derive_context_cmd_output_t dc_output = {0};
    struct certify_key_cmd_input_t ck_input = DEFAULT_CK_CMD_INPUT;
    struct certify_key_cmd_output_t ck_output = {0};

    ADD_CERT_CHAIN_BUF(ck_output, 1);
    ADD_DERIVED_PUB_KEY_BUF(ck_output, DPE_ATTEST_PUB_KEY_SIZE);

    dc_input.context_handle = retained_rot_ctx_handle;
    dc_input.create_certificate = true;

    dpe_err = CALL_DERIVE_CONTEXT(dc_input, dc_output);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveContext call failed");
        return;
    }

    ck_input.context_handle = dc_output.out_ctx_handle;

    dpe_err = CALL_CERTIFY_KEY(ck_input, ck_output);
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE CertifyKey test: Smaller certificate buffer size should return invalid argument");
        return;
    }

    /* Save the last handle for the subsequent test */
    retained_rot_ctx_handle = dc_output.out_parent_handle;
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);

    /* Since certificate buffer size is checked by client side API implementation,
     * it derives a valid DPE context within the service, so destroy that context
     */
    DESTROY_SINGLE_CONTEXT(ck_output.new_context_handle);

    ret->val = TEST_PASSED;
}

void certify_key_smaller_derived_pub_key_buffer_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    struct derive_context_cmd_input_t dc_input = DEFAULT_DC_CMD_INPUT;
    struct derive_context_cmd_output_t dc_output = {0};
    struct certify_key_cmd_input_t ck_input = DEFAULT_CK_CMD_INPUT;
    struct certify_key_cmd_output_t ck_output = {0};

    ADD_CERT_CHAIN_BUF(ck_output, 1100);
    ADD_DERIVED_PUB_KEY_BUF(ck_output, 1);

    dc_input.context_handle = retained_rot_ctx_handle;
    dc_input.create_certificate = true;

    dpe_err = CALL_DERIVE_CONTEXT(dc_input, dc_output);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveContext call failed");
        return;
    }

    ck_input.context_handle = dc_output.out_ctx_handle;

    dpe_err = CALL_CERTIFY_KEY(ck_input, ck_output);
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE CertifyKey test: Smaller public key buffer size should return invalid argument");
        return;
    }

    /* Save the last handle for the subsequent test */
    retained_rot_ctx_handle = dc_output.out_parent_handle;
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);

    /* Since public key buffer size is checked by client side API implementation,
     * it derives a valid DPE context within the service, so destroy that context
     */
    DESTROY_SINGLE_CONTEXT(ck_output.new_context_handle);

    ret->val = TEST_PASSED;
}

void certify_key_invalid_cbor_encoded_input_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    struct derive_context_cmd_input_t dc_input = DEFAULT_DC_CMD_INPUT;
    struct derive_context_cmd_output_t dc_output = {0};
    struct certify_key_cmd_input_t ck_input = DEFAULT_CK_CMD_INPUT;
    struct certify_key_cmd_output_t ck_output = {0};
    struct dpe_certify_key_test_params_t test_params = {0};

    ADD_CERT_CHAIN_BUF(ck_output, 10);
    ADD_DERIVED_PUB_KEY_BUF(ck_output, 10);

    dc_input.context_handle = retained_rot_ctx_handle;
    dc_input.create_certificate = true;

    dpe_err = CALL_DERIVE_CONTEXT(dc_input, dc_output);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveContext call failed");
        return;
    }

    /* Call test encode function with is_encoded_cbor_corrupt = true */
    test_params.is_encoded_cbor_corrupt = true;
    ck_input.context_handle = dc_output.out_ctx_handle;
    dpe_err = CALL_CERTIFY_KEY_WITH_TEST_PARAM(ck_input, ck_output, test_params);
    if (dpe_err != DPE_INVALID_COMMAND) {
        TEST_FAIL("DPE CertifyKey test: Invalid CBOR construct should return invalid command");
        return;
    }

    /* Destroy other derived contexts for subsequent test */
    DESTROY_SINGLE_CONTEXT(dc_output.out_ctx_handle);

    /* Save the last handle for the subsequent test */
    retained_rot_ctx_handle = dc_output.out_parent_handle;
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);

    ret->val = TEST_PASSED;
}

void certify_key_with_unsupported_params_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    struct certify_key_cmd_input_t ck_input = DEFAULT_CK_CMD_INPUT;
    struct certify_key_cmd_output_t ck_output = {0};
    struct dpe_certify_key_test_params_t test_params = {0};

    ADD_CERT_CHAIN_BUF(ck_output, 1100);
    ADD_DERIVED_PUB_KEY_BUF(ck_output, 1);

    ck_input.context_handle = retained_rot_ctx_handle;
    test_params.is_unsupported_params_added = true;
    dpe_err = CALL_CERTIFY_KEY_WITH_TEST_PARAM(ck_input, ck_output, test_params);
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE CertifyKey test: With unsupported parameters should fail");
        return;
    }

    ret->val = TEST_PASSED;
}

void certify_key_without_optional_args_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    struct derive_context_cmd_input_t dc_input = DEFAULT_DC_CMD_INPUT;
    struct derive_context_cmd_output_t dc_output = {0};
    struct certify_key_cmd_input_t ck_input = DEFAULT_CK_CMD_INPUT;
    struct certify_key_cmd_output_t ck_output = {0};
    struct dpe_certify_key_test_params_t test_params = {0};

    ADD_EXPORT_CDI_BUF(dc_output, 1);
    ADD_CERT_CHAIN_BUF(ck_output, 2500);
    ADD_DERIVED_PUB_KEY_BUF(ck_output, DPE_ATTEST_PUB_KEY_SIZE);

    dc_input.context_handle = retained_rot_ctx_handle;
    dc_input.create_certificate = true;
    dc_input.cert_id = DPE_UNDESTROYABLE_CTX_CERT_ID_4;

    dpe_err = CALL_DERIVE_CONTEXT(dc_input, dc_output);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveContext call failed");
        return;
    }
    retained_rot_ctx_handle = dc_output.out_parent_handle;
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);

    test_params.is_public_key_missing = true;
    ck_input.context_handle = dc_output.out_ctx_handle;
    dpe_err = CALL_CERTIFY_KEY_WITH_TEST_PARAM(ck_input, ck_output, test_params);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE CertifyKey test: Without optional parameter should not fail");
        return;
    }
    // TODO: If public key is omitted, key pair should be derived from context and label.
    //       Validate it.
    if (ck_output.derived_public_key_actual_size == 0) {
        TEST_FAIL("DPE CertifyKey test: Without optional parameter should not fail");
        return;
    }

    test_params.is_public_key_missing = false;
    test_params.is_label_missing = true;
    ck_input.context_handle = ck_output.new_context_handle;
    ck_output.derived_public_key_actual_size = 0;
    dpe_err = CALL_CERTIFY_KEY_WITH_TEST_PARAM(ck_input, ck_output, test_params);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE CertifyKey test: Without optional parameter should not fail");
        return;
    }
    // TODO: If label is omitted, empty label should be used for key derivation. Validate it.
    if (ck_output.derived_public_key_actual_size == 0) {
        TEST_FAIL("DPE CertifyKey test: Without optional parameter should not fail");
        return;
    }

    test_params.is_label_missing = false;
    test_params.is_retain_context_missing = true;
    ck_input.context_handle = ck_output.new_context_handle;
    /* This test will create undestroyable context as default value of
     * retain_context is false
     */
    dpe_err = CALL_CERTIFY_KEY_WITH_TEST_PARAM(ck_input, ck_output, test_params);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE CertifyKey test: Without optional parameter should not fail");
        return;
    }
    /* Default value of retain_context = false, hence it should NOT
     * return valid context handle
     */
    if (ck_output.new_context_handle != INVALID_HANDLE) {
        TEST_FAIL("DPE CertifyKey test: Without optional parameter should not fail");
        return;
    }

    ret->val = TEST_PASSED;
}

void certify_key_mixing_cert_id_multiple_ctx_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int err;
    const struct dpe_test_data_t *td = &test_data[4];
    struct certify_key_cmd_input_t ck_input = DEFAULT_CK_CMD_INPUT;
    struct certify_key_cmd_output_t ck_output = {0};
    ADD_CERT_CHAIN_BUF(ck_output, 2000);
    ADD_DERIVED_PUB_KEY_BUF(ck_output, DPE_ATTEST_PUB_KEY_SIZE);

    err = build_certificate_chain(td);
    if (err) {
        TEST_FAIL("Building certificate chain based on test data failed");
        return;
    }

    /* Use the last handle for the CertifyKey call */
    ck_input.context_handle = get_last_context_handle(td);

    dpe_err = CALL_CERTIFY_KEY(ck_input, ck_output);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE CertifyKey call failed");
        return;
    }

    /* Update renewed output handle from CertifyKey command */
    update_context_handle(td, ck_input.context_handle, ck_output.new_context_handle);

    /* Destroy the saved contexts for the subsequent test */
    err = destroy_multiple_context(td);
    if (err) {
        TEST_FAIL("DPE DestroyContext call failed");
        return;
    }

    ret->val = TEST_PASSED;
}
