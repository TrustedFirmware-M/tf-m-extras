/*
 * Copyright (c) 2023-2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <string.h>
#include "dice_protection_environment.h"
#include "dpe_certificate_decode.h"
#include "dpe_test.h"
#include "dpe_test_data.h"

#define CALL_CERTIFY_KEY_WITH_TEST_PARAM() \
        dpe_certify_key_with_test_param(out_ctx_handle, /* input_ctx_handle */  \
              true,                             /* retain_context */            \
              NULL,                             /* public_key */                \
              0,                                /* public_key_size */           \
              NULL,                             /* label */                     \
              0,                                /* label_size */                \
              certificate_buf,                  /* certificate_buf */           \
              sizeof(certificate_buf),          /* certificate_buf_size */      \
              &certificate_actual_size,         /* certificate_actual_size */   \
              derived_public_key_buf,           /* derived_public_key_buf */    \
              sizeof(derived_public_key_buf),   /* derived_public_key_buf_size */           \
              &derived_public_key_actual_size,  /* derived_public_key_buf_actual_size */    \
              &new_context_handle,              /* new_context_handle */        \
              &test_params);                    /* test_params */

extern struct dpe_derive_context_test_data_t
              derive_context_test_dataset_1[DERIVE_CONTEXT_TEST_DATA1_SIZE];
extern struct dpe_derive_context_test_data_t
              derive_context_test_dataset_2;
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

static void get_and_verify_certificate_chain(
                        struct test_result_t *ret,
                        int in_handle,
                        psa_key_id_t *pub_key_id,
                        int *saved_handles,
                        int *saved_handles_cnt,
                        int *out_ctx_handle)
{
    uint8_t certificate_buf[1650];
    size_t certificate_actual_size;
    UsefulBufC cert_chain_buf;
    dpe_error_t dpe_err;
    struct certificate_chain cert_chain = {0};
    int err, i;

    dpe_err = dpe_get_certificate_chain(in_handle,
                                        true, /* retain_context */
                                        false, /* clear_from_context */
                                        certificate_buf,
                                        sizeof(certificate_buf),
                                        &certificate_actual_size,
                                        out_ctx_handle);

    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE GetCertificateChain call failed");
        return;
    }

    /* Update renewed output handle from GetCertificateChain command */
    for (i = 0; i < *saved_handles_cnt; i++) {
        if (GET_IDX(*out_ctx_handle) == GET_IDX(saved_handles[i])) {
            saved_handles[i] = *out_ctx_handle;
        }
    }

    cert_chain_buf = (UsefulBufC){ certificate_buf,
                                   certificate_actual_size };

    err = verify_certificate_chain(cert_chain_buf, &cert_chain, pub_key_id);
    if (err) {
        TEST_FAIL("DPE certificate chain verification failed");
        return;
    }
}

static void get_and_verify_leaf_certificate(
                        struct test_result_t *ret,
                        int in_handle,
                        psa_key_id_t pub_key_id,
                        int *saved_handles,
                        int *saved_handles_cnt)
{
    uint8_t certificate_buf[1650];
    size_t certificate_actual_size;
    uint8_t derived_public_key_buf[DPE_ATTEST_PUB_KEY_SIZE];
    size_t derived_public_key_actual_size;
    UsefulBufC cert_buf;
    int new_context_handle, err, i;
    dpe_error_t dpe_err;
    struct certificate cert = {0};

    dpe_err = dpe_certify_key(in_handle,                        /* input_ctx_handle */
                              true,                             /* retain_context/ */
                              NULL,                             /* public_key */
                              0,                                /* public_key_size */
                              NULL,                             /* label */
                              0,                                /* label_size */
                              certificate_buf,                  /* certificate_buf */
                              sizeof(certificate_buf),          /* certificate_buf_size */
                              &certificate_actual_size,         /* certificate_actual_size */
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
    for (i = 0; i < *saved_handles_cnt; i++) {
        if (GET_IDX(new_context_handle) == GET_IDX(saved_handles[i])) {
            saved_handles[i] = new_context_handle;
        }
    }

    cert_buf = (UsefulBufC){ certificate_buf,
                             certificate_actual_size };
    err = verify_certificate(cert_buf, pub_key_id, &cert);
    if (err) {
        TEST_FAIL("DPE certificate chain verification failed");
        return;
    }

    err = unregister_pub_key(pub_key_id);
    if (err) {
        TEST_FAIL("DPE public key unregistration failed");
        return;
    }
}

/*
 * Test with finalized layer:
 *   - Build up the certificate chain based on derive_context_test_dataset_1.
 *   - Query the certificate chain and verify it. Get a reference to the
 *     public key in the last certificate.
 *   - Send a CertifyKey command to get a leaf certificate and verify it
 *     with the held reference to the public key coming from the last
 *     certificate.
 */
void certify_key_core_functionality_test_01(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    psa_key_id_t pub_key_id;
    int in_handle, out_ctx_handle;
    int i, saved_handles_cnt = 0;
    int saved_handles[MAX_NUM_OF_COMPONENTS] = {0};

    call_derive_context_with_test_data(
            ret,
            &derive_context_test_dataset_1[0],
            DERIVE_CONTEXT_TEST_DATA1_SIZE,
            saved_handles,
            &saved_handles_cnt,
            &out_ctx_handle);
    if (ret->val != TEST_PASSED) {
        return;
    }

    in_handle = out_ctx_handle;
    get_and_verify_certificate_chain(ret,
                                     in_handle,
                                     &pub_key_id,
                                     saved_handles,
                                     &saved_handles_cnt,
                                     &out_ctx_handle);
    if (ret->val != TEST_PASSED) {
        return;
    }

    in_handle = out_ctx_handle;
    get_and_verify_leaf_certificate(ret,
                                    in_handle,
                                    pub_key_id,
                                    saved_handles,
                                    &saved_handles_cnt);
    if (ret->val != TEST_PASSED) {
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

/*
 * Test with unfinished layer:
 *   - Query the certificate chain, contains only the RoT certificate, and
 *     verify it. Get a reference to the public key in the last certificate.
 *   - Build up the certificate chain based on derive_context_test_dataset_2.
 *   - Send a CertifyKey command to get a leaf certificate and verify it
 *     with the held reference to the public key coming from the last
 *     certificate.
 */
void certify_key_core_functionality_test_02(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    psa_key_id_t pub_key_id;
    int in_handle, out_ctx_handle;
    int i, saved_handles_cnt = 0;
    int saved_handles[MAX_NUM_OF_COMPONENTS] = {0};

    saved_handles_cnt = 0;
    in_handle = retained_rot_ctx_handle;
    get_and_verify_certificate_chain(ret,
                                     in_handle,
                                     &pub_key_id,
                                     saved_handles,
                                     &saved_handles_cnt,
                                     &out_ctx_handle);
    if (ret->val != TEST_PASSED) {
        return;
    }

    retained_rot_ctx_handle = out_ctx_handle;
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);

    call_derive_context_with_test_data(
            ret,
            &derive_context_test_dataset_2,
            DERIVE_CONTEXT_TEST_DATA2_SIZE,
            saved_handles,
            &saved_handles_cnt,
            &out_ctx_handle);
    if (ret->val != TEST_PASSED) {
        return;
    }

    in_handle = out_ctx_handle;
    get_and_verify_leaf_certificate(ret,
                                    in_handle,
                                    pub_key_id,
                                    saved_handles,
                                    &saved_handles_cnt);
    if (ret->val != TEST_PASSED) {
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

void certify_key_api_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int out_ctx_handle;
    const uint8_t label[] = { 0x1A, 0xBE, 0x1 };
    uint8_t certificate_buf[2000];
    size_t certificate_actual_size;
    uint8_t derived_public_key_buf[DPE_ATTEST_PUB_KEY_SIZE];
    size_t derived_public_key_actual_size;
    int new_context_handle;
    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;
    int out_parent_handle;

    dpe_err = dpe_derive_context(retained_rot_ctx_handle,       /* input_ctx_handle */
                                 DPE_PLATFORM_CERT_ID,          /* cert_id */
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
                              certificate_buf,                  /* certificate_buf */
                              sizeof(certificate_buf),          /* certificate_buf_size */
                              &certificate_actual_size,         /* certificate_actual_size */
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
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);

    ret->val = TEST_PASSED;
}

void certify_key_retain_context_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int out_ctx_handle;
    uint8_t certificate_buf[1300];
    size_t certificate_actual_size;
    uint8_t derived_public_key_buf[DPE_ATTEST_PUB_KEY_SIZE];
    size_t derived_public_key_actual_size;
    int new_context_handle;
    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;
    int out_parent_handle;

    dpe_err = dpe_derive_context(retained_rot_ctx_handle,       /* context_handle */
                                 DPE_UNDESTROYABLE_CTX_CERT_ID_3, /* cert_id */
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
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);

    dpe_err = dpe_certify_key(out_ctx_handle,                   /* input_ctx_handle */
                              false,                            /* retain_context */
                              NULL,                             /* public_key */
                              0,                                /* public_key_size */
                              NULL,                             /* label */
                              0,                                /* label_size */
                              certificate_buf,                  /* certificate_buf */
                              sizeof(certificate_buf),          /* certificate_buf_size */
                              &certificate_actual_size,         /* certificate_actual_size */
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

    /* Since retain_context is false, it will create undestroyable context */
    ret->val = TEST_PASSED;
}

void certify_key_incorrect_handle_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int out_ctx_handle, new_context_handle, out_parent_handle;
    uint8_t certificate_buf[10], derived_public_key_buf[10];
    size_t certificate_actual_size;
    size_t derived_public_key_actual_size;

    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;

    dpe_err = dpe_derive_context(retained_rot_ctx_handle,       /* input_ctx_handle */
                                 DPE_PLATFORM_CERT_ID,          /* cert_id */
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

    /* Use incorrect handle */
    dpe_err = dpe_certify_key(out_ctx_handle + 1,               /* input_ctx_handle */
                              true,                             /* retain_context */
                              NULL,                             /* public_key */
                              0,                                /* public_key_size */
                              NULL,                             /* label */
                              0,                                /* label_size */
                              certificate_buf,                  /* certificate_buf */
                              sizeof(certificate_buf),          /* certificate_buf_size */
                              &certificate_actual_size,         /* certificate_actual_size */
                              derived_public_key_buf,           /* derived_public_key_buf */
                              sizeof(derived_public_key_buf),   /* derived_public_key_buf_size */
                              &derived_public_key_actual_size,  /* derived_public_key_buf_actual_size */
                              &new_context_handle);             /* new_context_handle */
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE CertifyKey test: Invalid handle nonce should return invalid argument");
        return;
    }

    /* Destroy other derived contexts for subsequent test */
    dpe_err = dpe_destroy_context(out_ctx_handle, false);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DestroyContext call failed");
        return;
    }

    /* Save the last handle for the subsequent test */
    retained_rot_ctx_handle = out_parent_handle;
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
    int out_ctx_handle, new_context_handle, out_parent_handle;
    uint8_t certificate_buf[1];
    size_t certificate_actual_size;
    uint8_t derived_public_key_buf[DPE_ATTEST_PUB_KEY_SIZE];
    size_t derived_public_key_actual_size;
    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;

    dpe_err = dpe_derive_context(retained_rot_ctx_handle,       /* input_ctx_handle */
                                 DPE_PLATFORM_CERT_ID,          /* cert_id */
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
                              NULL,                             /* label */
                              0,                                /* label_size */
                              certificate_buf,                  /* certificate_buf */
                              sizeof(certificate_buf),          /* certificate_buf_size */
                              &certificate_actual_size,         /* certificate_actual_size */
                              derived_public_key_buf,           /* derived_public_key_buf */
                              sizeof(derived_public_key_buf),   /* derived_public_key_buf_size */
                              &derived_public_key_actual_size,  /* derived_public_key_buf_actual_size */
                              &new_context_handle);             /* new_context_handle */
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE CertifyKey test: Smaller certificate buffer size should return invalid argument");
        return;
    }

    /* Save the last handle for the subsequent test */
    retained_rot_ctx_handle = out_parent_handle;
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);

    /* Since certificate buffer size is checked by client side API implementation,
     * it derives a valid DPE context within the service, so destroy that context
     */
    dpe_err = dpe_destroy_context(new_context_handle, false);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DestroyContext call failed");
        return;
    }

    ret->val = TEST_PASSED;
}

void certify_key_smaller_derived_pub_key_buffer_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int out_ctx_handle, new_context_handle, out_parent_handle;
    uint8_t certificate_buf[1100];
    size_t certificate_actual_size;
    uint8_t derived_public_key_buf[1];
    size_t derived_public_key_actual_size;
    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;

    dpe_err = dpe_derive_context(retained_rot_ctx_handle,       /* input_ctx_handle */
                                 DPE_PLATFORM_CERT_ID,          /* cert_id */
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
                              NULL,                             /* label */
                              0,                                /* label_size */
                              certificate_buf,                  /* certificate_buf */
                              sizeof(certificate_buf),          /* certificate_buf_size */
                              &certificate_actual_size,         /* certificate_actual_size */
                              derived_public_key_buf,           /* derived_public_key_buf */
                              sizeof(derived_public_key_buf),   /* derived_public_key_buf_size */
                              &derived_public_key_actual_size,  /* derived_public_key_buf_actual_size */
                              &new_context_handle);             /* new_context_handle */
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE CertifyKey test: Smaller public key buffer size should return invalid argument");
        return;
    }

    /* Save the last handle for the subsequent test */
    retained_rot_ctx_handle = out_parent_handle;
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);

    /* Since public key buffer size is checked by client side API implementation,
     * it derives a valid DPE context within the service, so destroy that context
     */
    dpe_err = dpe_destroy_context(new_context_handle, false);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DestroyContext call failed");
        return;
    }

    ret->val = TEST_PASSED;
}

void certify_key_invalid_cbor_encoded_input_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int out_ctx_handle, new_context_handle, out_parent_handle;
    uint8_t certificate_buf[10];
    size_t certificate_actual_size;
    uint8_t derived_public_key_buf[10];
    size_t derived_public_key_actual_size;
    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;
    struct dpe_certify_key_test_params_t test_params = {0};

    dpe_err = dpe_derive_context(retained_rot_ctx_handle,       /* input_ctx_handle */
                                 DPE_PLATFORM_CERT_ID,          /* cert_id */
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

    /* Call test encode function with is_encoded_cbor_corrupt = true */
    test_params.is_encoded_cbor_corrupt = true;
    dpe_err = CALL_CERTIFY_KEY_WITH_TEST_PARAM();
    if (dpe_err != DPE_INVALID_COMMAND) {
        TEST_FAIL("DPE CertifyKey test: Invalid CBOR construct should return invalid command");
        return;
    }

    /* Destroy other derived contexts for subsequent test */
    dpe_err = dpe_destroy_context(out_ctx_handle, false);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DestroyContext call failed");
        return;
    }

    /* Save the last handle for the subsequent test */
    retained_rot_ctx_handle = out_parent_handle;
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);

    ret->val = TEST_PASSED;
}

void certify_key_with_unsupported_params_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int out_ctx_handle, new_context_handle;
    uint8_t certificate_buf[1100];
    size_t certificate_actual_size;
    uint8_t derived_public_key_buf[1];
    size_t derived_public_key_actual_size;
    struct dpe_certify_key_test_params_t test_params = {0};

    out_ctx_handle = retained_rot_ctx_handle;
    test_params.is_unsupported_params_added = true;
    dpe_err = CALL_CERTIFY_KEY_WITH_TEST_PARAM();
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE CertifyKey test: With unsupported parameters should fail");
        return;
    }

    ret->val = TEST_PASSED;
}

void certify_key_without_optional_args_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int out_ctx_handle, out_parent_handle, new_context_handle;
    uint8_t certificate_buf[2500];
    size_t certificate_actual_size;
    uint8_t derived_public_key_buf[DPE_ATTEST_PUB_KEY_SIZE];
    size_t derived_public_key_actual_size;
    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;
    struct dpe_certify_key_test_params_t test_params = {0};

    dpe_err = dpe_derive_context(retained_rot_ctx_handle,       /* input_ctx_handle */
                                 DPE_UNDESTROYABLE_CTX_CERT_ID_4, /* cert_id */
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
    retained_rot_ctx_handle = out_parent_handle;
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);

    test_params.is_public_key_missing = true;
    dpe_err = CALL_CERTIFY_KEY_WITH_TEST_PARAM();
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE CertifyKey test: Without optional parameter should not fail");
        return;
    }
    // TODO: If public key is omitted, key pair should be derived from context and label.
    //       Validate it.
    if (derived_public_key_actual_size == 0) {
        TEST_FAIL("DPE CertifyKey test: Without optional parameter should not fail");
        return;
    }

    test_params.is_public_key_missing = false;
    test_params.is_label_missing = true;
    out_ctx_handle = new_context_handle;
    derived_public_key_actual_size = 0;
    dpe_err = CALL_CERTIFY_KEY_WITH_TEST_PARAM();
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE CertifyKey test: Without optional parameter should not fail");
        return;
    }
    // TODO: If label is omitted, empty label should be used for key derivation. Validate it.
    if (derived_public_key_actual_size == 0) {
        TEST_FAIL("DPE CertifyKey test: Without optional parameter should not fail");
        return;
    }

    test_params.is_label_missing = false;
    test_params.is_retain_context_missing = true;
    out_ctx_handle = new_context_handle;
    /* This test will create undestroyable context as default value of
     * retain_context is false
     */
    dpe_err = CALL_CERTIFY_KEY_WITH_TEST_PARAM();
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE CertifyKey test: Without optional parameter should not fail");
        return;
    }
    /* Default value of retain_context = false, hence it should NOT
     * return valid context handle
     */
    if (new_context_handle != INVALID_HANDLE) {
        TEST_FAIL("DPE CertifyKey test: Without optional parameter should not fail");
        return;
    }

    ret->val = TEST_PASSED;
}
