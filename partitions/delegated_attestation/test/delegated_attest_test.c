/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2022 Cypress Semiconductor Corporation (an Infineon company)
 * or an affiliate of Cypress Semiconductor Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "delegated_attest_test.h"
#include "test_framework.h"
#include "tfm_delegated_attestation.h"
#include "psa/crypto.h"
#include "psa/error.h"
#include <stddef.h>
#include <stdint.h>

/* Platform attestation token buffer */
static uint8_t token_buf[PLATFORM_TOKEN_BUFF_SIZE];
/* Delegated attestation key buffer */
static uint8_t dak_buf[DELEGATED_ATTEST_KEY_MAX_SIZE];

#ifdef DELEG_ATTEST_DUMP_TOKEN_AND_KEY
static void dump_data(unsigned char *buf, size_t len, const char *prefix)
{
    int i;
    unsigned char num;

    for (i = 0; i < len; ++i) {
        num = buf[i];
        if ((i % 16) == 0) {
            TEST_LOG("%s", prefix);
        }
        TEST_LOG("%x%x ", (num & 0xF0) >> 4, num & 0x0F);
        if (((i + 1) % 16) == 0) {
            TEST_LOG("\n");
        }
    }
    TEST_LOG("\n");
}
#endif

static int calc_public_dak_hash(const uint8_t *dak_buf,
                                uint32_t       dak_bits,
                                uint8_t       *dak_pub_hash_buf,
                                size_t         dak_pub_hash_buf_size,
                                size_t        *dak_pub_hash_len)
{
    psa_status_t status;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t dak_id;
    uint8_t dak_pub_buf[PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(521)];
    size_t dak_pub_len;

    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(
                                DELEGATED_ATTEST_KEY_ELLIPTIC_CURVE));
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_384));
    psa_set_key_bits(&attr, dak_bits);

    status = psa_import_key(&attr, dak_buf, PSA_BITS_TO_BYTES(dak_bits), &dak_id);
    if (status != PSA_SUCCESS) {
        return 10;
    }

    /* Export the public part of the delegated attestation key (DAK). */
    status = psa_export_public_key(dak_id,
                                   dak_pub_buf,
                                   sizeof(dak_pub_buf),
                                   &dak_pub_len);
    if (status != PSA_SUCCESS) {
        return 20;
    }

    /* Calculate the hash of public part of the delegated attestation key. */
    status = psa_hash_compute(DELEGATED_ATTEST_KEY_HASH_ALGO,
                              dak_pub_buf, dak_pub_len,
                              dak_pub_hash_buf, dak_pub_hash_buf_size,
                              dak_pub_hash_len);
    if (status != PSA_SUCCESS) {
        return 30;
    }

    return 0;
}

/*
 * Public function. See delegated_attest_test.h
 */
void tfm_delegated_attest_test_1001(struct test_result_t *ret)
{
    uint8_t dak_pub_hash_buf[DELEGATED_ATTEST_KEY_HASH_SIZE];
    size_t  dak_pub_hash_len;
    size_t token_len;
    size_t dak_len;
    psa_status_t status;
    int err;

    /* Test the calling sequence.
     * Correct sequence:
     *  - tfm_delegated_attest_get_delegated_key()
     *  - tfm_delegated_attest_get_token()
     * In this case the first call is missing so the expectation to return with
     * PSA_ERROR_INVALID_ARGUMENT.
     */
    status = tfm_delegated_attest_get_token(dak_pub_hash_buf,
                                            sizeof(dak_pub_hash_buf),
                                            token_buf,
                                            sizeof(token_buf),
                                            &token_len);
    if (status != PSA_ERROR_INVALID_ARGUMENT) {
        TEST_LOG("tfm_delegated_attest_get_token() failed, returned: %d\r\n", status);
        TEST_LOG("Delegated attestation token request should fail with invalid calling sequence");
        ret->val = TEST_FAILED;
        return;
    }

    /* Make the calls in correct sequence */
    status = tfm_delegated_attest_get_delegated_key(
              DELEGATED_ATTEST_KEY_ELLIPTIC_CURVE,
              DELEGATED_ATTEST_KEY_BIT_SIZE,
              dak_buf,
              sizeof(dak_buf),
              &dak_len,
              DELEGATED_ATTEST_KEY_HASH_ALGO);
    if (status != PSA_SUCCESS) {
        TEST_LOG("tfm_delegated_attest_get_delegated_key() failed, returned: %d\r\n", status);
        TEST_LOG("DAK request should succeed with valid parameters");
        ret->val = TEST_FAILED;
        return;
    }

    if (dak_len != PSA_BITS_TO_BYTES(DELEGATED_ATTEST_KEY_BIT_SIZE)) {
        TEST_LOG("DAK length does not match to key bit size");
        ret->val = TEST_FAILED;
        return;
    }

#ifdef DELEG_ATTEST_DUMP_TOKEN_AND_KEY
/* Print delegated attest key in TF-A log style to be able to process it in the
 * attestation verification script.
 *
 * Keep this print unchanged, the log processing script expects to be present.
 */
TEST_LOG("\nINFO:    Delegated attest key:\n");
dump_data(dak_buf, dak_len, "INFO:    ");
#endif

    /* Calculate the hash of the public part of the delegated attestation key */
    err = calc_public_dak_hash(dak_buf,
                               DELEGATED_ATTEST_KEY_BIT_SIZE,
                               dak_pub_hash_buf,
                               sizeof(dak_pub_hash_buf),
                               &dak_pub_hash_len);
    if (err != 0) {
        TEST_LOG("calc_public_dak_hash() failed, returned: %d\r\n", err);
        TEST_LOG("Should succeed after delegated key is successfully requested");
        ret->val = TEST_FAILED;
        return;
    }

    status = tfm_delegated_attest_get_token(dak_pub_hash_buf,
                                            dak_pub_hash_len,
                                            token_buf,
                                            sizeof(token_buf),
                                            &token_len);
    if (status != PSA_SUCCESS) {
        TEST_LOG("tfm_delegated_attest_get_token() failed, returned: %d\r\n", status);
        TEST_LOG("Delegated attestation token request should succeed with valid parameters");
        ret->val = TEST_FAILED;
        return;
    }

#ifdef DELEG_ATTEST_DUMP_TOKEN_AND_KEY
/* Print the token in TF-A log style to be able to process it in attestation
 * script.
 *
 * Keep this print unchanged, the log processing script expects to be present.
 */
TEST_LOG("\nINFO:    Platform attestation token:\n");
dump_data(token_buf, token_len, "INFO:    ");
/* This marks the end of the log to be processed. Keep it unchanged. */
TEST_LOG("INFO: End of delegated attest basic test\n");
#endif

    /* TODO: Validate the platform attestation token */

    /* Negative test: Check if dak_pub_hash doesn't match with expected value */
    dak_pub_hash_buf[0] ^= 1 << 7; /* Toggle the first bit */
    status = tfm_delegated_attest_get_token(dak_pub_hash_buf, /* Invalid */
                                            dak_pub_hash_len,
                                            token_buf,
                                            sizeof(token_buf),
                                            &token_len);
    if (status != PSA_ERROR_INVALID_ARGUMENT) {
        TEST_LOG("tfm_delegated_attest_get_token() failed, returned: %d\r\n", status);
        TEST_LOG("Delegated attestation token request should fail with invalid parameters");
        ret->val = TEST_FAILED;
        return;
    }

    dak_pub_hash_buf[0] ^= 1 << 7; /* Toggle the first bit */
    /* Negative test: size of the hash value is invalid */
    status = tfm_delegated_attest_get_token(dak_pub_hash_buf,
                                            dak_pub_hash_len - 1, /* Invalid */
                                            token_buf,
                                            sizeof(token_buf),
                                            &token_len);
    if (status != PSA_ERROR_INVALID_ARGUMENT) {
        TEST_LOG("tfm_delegated_attest_get_token() failed, returned: %d\r\n", status);
        TEST_LOG("Delegated attestation token request should fail with invalid parameters");
        ret->val = TEST_FAILED;
        return;
    }

    /* Negative test: token_buf is too small (other than 0) */
    status = tfm_delegated_attest_get_token(dak_pub_hash_buf,
                                            dak_pub_hash_len,
                                            token_buf,
                                            1u, /* Invalid */
                                            &token_len);
    if (status != PSA_ERROR_BUFFER_TOO_SMALL) {
        TEST_LOG("tfm_delegated_attest_get_token() failed, returned: %d\r\n", status);
        TEST_LOG("Delegated attestation token request should fail with invalid parameters");
        ret->val = TEST_FAILED;
        return;
    }

    /* Just make a final call with the right set of parameters */
    status = tfm_delegated_attest_get_token(dak_pub_hash_buf,
                                            dak_pub_hash_len,
                                            token_buf,
                                            sizeof(token_buf),
                                            &token_len);
    if (status != PSA_SUCCESS) {
        TEST_LOG("tfm_delegated_attest_get_token() failed, returned: %d\r\n", status);
        TEST_LOG("Delegated attestation token request should succeed with valid parameters");
        ret->val = TEST_FAILED;
        return;
    }

    ret->val = TEST_PASSED;
}

/*
 * Public function. See delegated_attest_test.h
 */
void tfm_delegated_attest_test_1002(struct test_result_t *ret)
{
    size_t key_bits[] = {256, 384, 521};
    size_t dak_len;
    psa_algorithm_t hash_algos[] = {PSA_ALG_SHA_256,
                                    PSA_ALG_SHA_384,
                                    PSA_ALG_SHA_512};
    int i;
    psa_status_t err = PSA_SUCCESS;

    for (i = 0; i < (sizeof(key_bits) / sizeof(key_bits[0])); i++) {
        err = tfm_delegated_attest_get_delegated_key(
                  DELEGATED_ATTEST_KEY_ELLIPTIC_CURVE,
                  key_bits[i],
                  dak_buf,
                  sizeof(dak_buf),
                  &dak_len,
                  DELEGATED_ATTEST_KEY_HASH_ALGO);
        if (err != PSA_SUCCESS) {
            TEST_LOG("tfm_delegated_attest_get_delegated_key() failed, returned: %d\r\n", err);
            TEST_LOG("DAK request should succeed with valid parameters");
            ret->val = TEST_FAILED;
            return;
        }
        if (dak_len != PSA_BITS_TO_BYTES(key_bits[i])) {
            TEST_LOG("key_bits: %d", key_bits[i]);
            TEST_LOG("DAK length does not match to key bit size");
            ret->val = TEST_FAILED;
            return;
        }
    }

    for (i = 0; i < (sizeof(hash_algos) / sizeof(hash_algos[0])); i++) {
        err = tfm_delegated_attest_get_delegated_key(
                  DELEGATED_ATTEST_KEY_ELLIPTIC_CURVE,
                  DELEGATED_ATTEST_KEY_BIT_SIZE,
                  dak_buf,
                  sizeof(dak_buf),
                  &dak_len,
                  hash_algos[i]);
        if (err != PSA_SUCCESS) {
            TEST_LOG("tfm_delegated_attest_get_delegated_key() failed, returned: %d\r\n", err);
            TEST_LOG("DAK request should succeed with valid parameters");
            ret->val = TEST_FAILED;
            return;
        }
    }

    ret->val = TEST_PASSED;
}

/*
 * Public function. See delegated_attest_test.h
 */
void tfm_delegated_attest_test_1003(struct test_result_t *ret)
{
    uint8_t dak_pub_hash_buf[DELEGATED_ATTEST_KEY_HASH_SIZE];
    size_t dak_len;
    psa_status_t err;

    /* Negative test: Invalid curve type */
    err = tfm_delegated_attest_get_delegated_key(
              PSA_ECC_FAMILY_SECP_K1, /* Invalid */
              DELEGATED_ATTEST_KEY_BIT_SIZE,
              dak_buf,
              sizeof(dak_buf),
              &dak_len,
              DELEGATED_ATTEST_KEY_HASH_ALGO);
    if (err != PSA_ERROR_INVALID_ARGUMENT) {
        TEST_LOG("tfm_delegated_attest_get_delegated_key() failed, returned: %d\r\n", err);
        TEST_LOG("DAK request should fail with invalid parameters");
        ret->val = TEST_FAILED;
        return;
    }

    /* Negative test: Invalid key_bits */
    err = tfm_delegated_attest_get_delegated_key(
              DELEGATED_ATTEST_KEY_ELLIPTIC_CURVE,
              224, /* Invalid */
              dak_buf,
              sizeof(dak_buf),
              &dak_len,
              DELEGATED_ATTEST_KEY_HASH_ALGO);
    if (err != PSA_ERROR_INVALID_ARGUMENT) {
        TEST_LOG("tfm_delegated_attest_get_delegated_key() failed, returned: %d\r\n", err);
        TEST_LOG("DAK request should fail with invalid parameters");
        ret->val = TEST_FAILED;
        return;
    }

    /*
     * Negative test: if dak_buf is NULL, then PSA framwork panics therfore it
     * is not implemented.
     */

    /* Negative test: dak_buf is too small */
    err = tfm_delegated_attest_get_delegated_key(
              DELEGATED_ATTEST_KEY_ELLIPTIC_CURVE,
              DELEGATED_ATTEST_KEY_BIT_SIZE,
              dak_buf,
              PSA_BITS_TO_BYTES(DELEGATED_ATTEST_KEY_BIT_SIZE) - 1, /* Invalid */
              &dak_len,
              DELEGATED_ATTEST_KEY_HASH_ALGO);
    if (err != PSA_ERROR_BUFFER_TOO_SMALL) {
        TEST_LOG("tfm_delegated_attest_get_delegated_key() failed, returned: %d\r\n", err);
        TEST_LOG("DAK request should fail with invalid parameters");
        ret->val = TEST_FAILED;
        return;
    }

    /* Negative test: &dak_len is NULL */
    err = tfm_delegated_attest_get_delegated_key(
              DELEGATED_ATTEST_KEY_ELLIPTIC_CURVE,
              DELEGATED_ATTEST_KEY_BIT_SIZE,
              dak_buf,
              sizeof(dak_buf),
              NULL, /* Invalid */
              DELEGATED_ATTEST_KEY_HASH_ALGO);
    if (err != PSA_ERROR_INVALID_ARGUMENT) {
        TEST_LOG("tfm_delegated_attest_get_delegated_key() failed, returned: %d\r\n", err);
        TEST_LOG("DAK request should fail with invalid parameters");
        ret->val = TEST_FAILED;
        return;
    }

    /* Negative test: unsupported hash_algo */
    err = tfm_delegated_attest_get_delegated_key(
              DELEGATED_ATTEST_KEY_ELLIPTIC_CURVE,
              DELEGATED_ATTEST_KEY_BIT_SIZE,
              dak_buf,
              sizeof(dak_buf),
              &dak_len,
              PSA_ALG_SHA3_512 + 1); /* Invalid */
    if (err == PSA_SUCCESS) {
        TEST_LOG("tfm_delegated_attest_get_delegated_key() failed, returned: %d\r\n", err);
        TEST_LOG("DAK request should fail with invalid parameters");
        ret->val = TEST_FAILED;
        return;
    }

    ret->val = TEST_PASSED;
}
