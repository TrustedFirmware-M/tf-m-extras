/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stddef.h>
#include <stdint.h>
#include "delegated_attest.h"
#include "psa/client.h"
#include "psa/crypto.h"
#include "psa/error.h"
#include "psa/service.h"
#include "psa_manifest/tfm_delegated_attestation.h"
#include "region_defs.h"
#include "tfm_delegated_attest_defs.h"

#define DELEGATED_ATTEST_KEY_MAX_SIZE PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(521)
/* Buffer to store the derived delegated attestation key. */
static uint8_t dak_buf[DELEGATED_ATTEST_KEY_MAX_SIZE];
/* Buffer to store the created platform attestation token. */
static uint8_t token_buf[PSA_INITIAL_ATTEST_TOKEN_MAX_SIZE];

static psa_status_t get_delegated_attestation_key(const psa_msg_t *msg)
{
    psa_ecc_family_t ecc_curve;
    psa_algorithm_t hash_algo;
    psa_status_t status;
    uint32_t key_bits;
    size_t   key_buf_size;
    size_t   key_len;
    size_t bytes_read;

    /* Check input parameters */
    if (msg->in_size[0] != sizeof(ecc_curve) ||
        msg->in_size[1] != sizeof(key_bits)  ||
        msg->in_size[2] != sizeof(hash_algo)) {
        return PSA_ERROR_PROGRAMMER_ERROR;
    }

    bytes_read = psa_read(msg->handle, 0, &ecc_curve, sizeof(ecc_curve));
    if (bytes_read != sizeof(ecc_curve)) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    bytes_read = psa_read(msg->handle, 1, &key_bits, sizeof(key_bits));
    if (bytes_read != sizeof(key_bits)) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    bytes_read = psa_read(msg->handle, 2, &hash_algo, sizeof(hash_algo));
    if (bytes_read != sizeof(hash_algo)) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    /* COSE standard defines ECDSA to work only with these curves:
     * P-256, P-384, and P-521.
     * https://datatracker.ietf.org/doc/html/rfc8152#section-8.1
     */
    if (ecc_curve != PSA_ECC_FAMILY_SECP_R1) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (key_bits != 256 && key_bits != 384 && key_bits != 521) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Check output parameters */
    if (msg->out_size[0] < PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(key_bits)) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    key_buf_size = msg->out_size[0] < sizeof(dak_buf) ?
                   msg->out_size[0] : sizeof(dak_buf);

    status = delegated_attest_get_delegated_key(ecc_curve, key_bits,
                                                dak_buf, key_buf_size,
                                                &key_len, hash_algo);
    if (status == PSA_SUCCESS) {
        psa_write(msg->handle, 0, dak_buf, key_len);
    }

    return status;
}

static psa_status_t get_platform_attestation_token(const psa_msg_t *msg)
{
    psa_status_t status;
    uint8_t dak_pub_hash[PSA_HASH_LENGTH(PSA_ALG_SHA_512)];
    size_t  dak_pub_hash_size;
    size_t token_buf_size;
    size_t token_size;
    size_t bytes_read;

    dak_pub_hash_size = msg->in_size[0];
    bytes_read = psa_read(msg->handle, 0, dak_pub_hash, dak_pub_hash_size);
    if (bytes_read != dak_pub_hash_size) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    token_buf_size = msg->out_size[0] < sizeof(token_buf) ?
                     msg->out_size[0] : sizeof(token_buf);

    /* Check input parameters
     * Allowed nonce value lengths in attestation token: 32, 48, 64 bytes.
     */
    if (dak_pub_hash_size != PSA_HASH_LENGTH(PSA_ALG_SHA_256) &&
        dak_pub_hash_size != PSA_HASH_LENGTH(PSA_ALG_SHA_384) &&
        dak_pub_hash_size != PSA_HASH_LENGTH(PSA_ALG_SHA_512)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = delegated_attest_get_platform_token(dak_pub_hash,
                                                 dak_pub_hash_size,
                                                 token_buf,
                                                 token_buf_size,
                                                 &token_size);
    if (status == PSA_SUCCESS) {
        psa_write(msg->handle, 0, token_buf, token_size);
    }

    return status;
}

static void delegated_attestation_signal_handle(psa_signal_t signal)
{
    psa_status_t status;
    psa_msg_t msg;

    /* Retrieve the message corresponding to the
     * Delegated Attestation service signal.
     */
    status = psa_get(signal, &msg);
    if (status != PSA_SUCCESS) {
        return;
    }

    switch (msg.type) {
    case DELEGATED_ATTEST_GET_DELEGATED_KEY:
        status = get_delegated_attestation_key(&msg);
        /* Reply with the message result status to unblock the client */
        psa_reply(msg.handle, status);
        break;
    case DELEGATED_ATTEST_GET_PLATFORM_TOKEN:
        status = get_platform_attestation_token(&msg);
        /* Reply with the message result status to unblock the client */
        psa_reply(msg.handle, status);
        break;
    default:
        /* Invalid message type */
        psa_panic();
    }
}

void delegated_attest_partition_main(void)
{
    psa_signal_t signals = 0;

    /* Delegated Attestation partition initialization.
     * - Nothing to do -
     */

    while (1) {
        signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);
        if (signals & TFM_DELEGATED_ATTESTATION_SIGNAL) {
            delegated_attestation_signal_handle(TFM_DELEGATED_ATTESTATION_SIGNAL);
        } else {
            /* Should not come here */
            psa_panic();
        }
    }
}
