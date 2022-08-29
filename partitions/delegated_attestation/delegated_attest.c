/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "delegated_attest.h"
#include "psa/crypto.h"
#include "psa/initial_attestation.h"
#include "region_defs.h"
#include "tfm_attest_iat_defs.h"
#include "tfm_crypto_defs.h"
#include "measured_boot_api.h"
#include "qcbor.h"
#include "q_useful_buf.h"

/* Delegated attestation key (DAK) identifier */
static psa_key_id_t dak_key_id = PSA_KEY_ID_NULL;
/* Keeps track of whether DAK has been requested */
static bool dak_requested = false;
/* Buffer to store the encoded platform boot state */
static uint8_t boot_state_buffer[TFM_ATTEST_BOOT_RECORDS_MAX_SIZE];
/* Hash algorithm that is used by the owner of the DAK for calculating the
 * digest of the public part of the key (it serves as an input when creating
 * the platform attestation token).
 */
static psa_algorithm_t dak_pub_hash_algo = PSA_ALG_NONE;

/**
 * \brief Static function to verify the hash of the public DAK
 *
 * \param[in]  dak_pub_hash      Pointer to buffer where the hash of the
 *                               public DAK is stored.
 * \param[in]  dak_pub_hash_len  Length of the hash value, in bytes.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
static psa_status_t
verify_dak_pub_hash(const uint8_t *dak_pub_hash, size_t dak_pub_hash_len)
{
    psa_status_t status;
    /* Buffer large enough for P-521 public key */
    uint8_t pub_key_buf[PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(521)];
    size_t  pub_key_len;

    /* Verify the size of the hash */
    if (dak_pub_hash_len != PSA_HASH_LENGTH(dak_pub_hash_algo)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Export the public part of the DAK */
    status = psa_export_public_key(dak_key_id,
                                   pub_key_buf,
                                   sizeof(pub_key_buf),
                                   &pub_key_len);
    if (status != PSA_SUCCESS) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    /* Calculate and compare the hash of the public DAK */
    status = psa_hash_compare(dak_pub_hash_algo,
                              pub_key_buf, pub_key_len,
                              dak_pub_hash, dak_pub_hash_len);
    if (status != PSA_SUCCESS) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return status;
}

/**
 * \brief Static function to get a string representing the measurement algorithm
 *
 * String names according to
 * https://www.iana.org/assignments/hash-function-text-names/hash-function-text-names.xhtml
 *
 *  \param[in]   algorithm        Algorithm identifier
 * \param[out]  measurement_desc Structure to carry the output string:
 *                               pointer + string length, not including
 *                               the null-terminator
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
static inline psa_status_t
get_firmware_measurement_description(psa_algorithm_t algorithm,
                                     struct q_useful_buf_c *measurement_desc)
{
    switch (algorithm) {
    case PSA_ALG_SHA_256:
        measurement_desc->ptr = "sha-256";
        break;
    case PSA_ALG_SHA_384:
        measurement_desc->ptr = "sha-384";
        break;
    case PSA_ALG_SHA_512:
        measurement_desc->ptr = "sha-512";
        break;
    default:
        /* Algorithm not supported. */
        return PSA_ERROR_NOT_SUPPORTED;
    }
    measurement_desc->len = 7; /* Not including the null-terminator. */

    return PSA_SUCCESS;
}

/**
 * \brief Encodes a firmware measurement and metadata as a map in CBOR
 *
 * \param[in]  encode_ctx        The encoding context to open the map in
 * \param[in]  signer_id         Pointer to buffer which stores the signer ID
 * \param[in]  sw_version        Pointer to buffer which stores the SW version
 * \param[in]  sw_type           Pointer to buffer which stores the SW type
 * \param[in]  measurement_desc  Pointer to buffer which stores the
 *                               measurement description
 * \param[in]  measurement       Pointer to buffer which stores the
 *                               measurement value
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
static psa_status_t
encode_firmware_measurement(QCBOREncodeContext *encode_ctx,
                            const struct q_useful_buf_c *signer_id,
                            const struct q_useful_buf_c *sw_version,
                            const struct q_useful_buf_c *sw_type,
                            const struct q_useful_buf_c *measurement_desc,
                            const struct q_useful_buf_c *measurement)
{
    if (encode_ctx == NULL || signer_id == NULL || sw_version == NULL ||
        sw_type == NULL || measurement_desc == NULL || measurement == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    QCBOREncode_OpenMap(encode_ctx);

    /* Encode signer ID as byte string. */
    QCBOREncode_AddBytesToMapN(encode_ctx,
                               IAT_SW_COMPONENT_SIGNER_ID,
                               *signer_id);

    /* Encode component version as text string. */
    QCBOREncode_AddTextToMapN(encode_ctx,
                              IAT_SW_COMPONENT_VERSION,
                              *sw_version);

    /* Encode software component type as text string. */
    QCBOREncode_AddTextToMapN(encode_ctx,
                              IAT_SW_COMPONENT_MEASUREMENT_TYPE,
                              *sw_type);

    /* Encode measurement description as text string. */
    QCBOREncode_AddTextToMapN(encode_ctx,
                              IAT_SW_COMPONENT_MEASUREMENT_DESC,
                              *measurement_desc);

    /* Encode measurement value as byte string. */
    QCBOREncode_AddBytesToMapN(encode_ctx,
                               IAT_SW_COMPONENT_MEASUREMENT_VALUE,
                               *measurement);

    QCBOREncode_CloseMap(encode_ctx);

    return PSA_SUCCESS;
}

/**
 * \brief Static function to return the boot state in CBOR encoded format
 *
 * The firmware measurements and associated firmware identity metadata together
 * form the boot state. This function returns a CBOR encoded array if
 * at least 1 firmware measurement is found, otherwise the \p boot_state_len
 * parameter is set to 0 on return.
 *
 * \param[out] boot_state         Pointer to the buffer where the encoded boot
 *                                state information will be stored.
 * \param[in,out] boot_state_len  As an input it is the size of the allocated
 *                                buffer for boot state in bytes. At return its
 *                                values is updated with the exact size of the
 *                                encoded boot state.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
static psa_status_t
get_platform_boot_state(uint8_t *boot_state, size_t *boot_state_len)
{

    psa_status_t status;
    QCBOREncodeContext encode_context;
    QCBORError encode_error;
    struct q_useful_buf boot_state_buf = {
        .ptr = boot_state,
        .len = *boot_state_len
    };
    struct q_useful_buf_c boot_state_buf_c = NULL_Q_USEFUL_BUF_C;
    struct q_useful_buf_c measurement_desc = NULL_Q_USEFUL_BUF_C;
    Q_USEFUL_BUF_MAKE_STACK_UB(measurement_buf, MEASUREMENT_VALUE_MAX_SIZE);
    Q_USEFUL_BUF_MAKE_STACK_UB(signer_id_buf, SIGNER_ID_MAX_SIZE);
    Q_USEFUL_BUF_MAKE_STACK_UB(sw_version_buf, VERSION_MAX_SIZE);
    Q_USEFUL_BUF_MAKE_STACK_UB(sw_type_buf, SW_TYPE_MAX_SIZE);
    uint32_t measurement_algo;
    uint32_t measurement_cnt;
    uint8_t slot_index;
    bool is_locked;

    if (q_useful_buf_is_null_or_empty(boot_state_buf)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Set up encoding context with output buffer. */
    QCBOREncode_Init(&encode_context, boot_state_buf);

    /* Retrieve all the measurements from the Measured Boot partition
     * which are accessible to the Delegated Attestation partition.
     */
    measurement_cnt = 0;
    for (slot_index = 0; slot_index < NUM_OF_MEASUREMENT_SLOTS; slot_index++) {
        status = tfm_measured_boot_read_measurement(slot_index,
                                                    signer_id_buf.ptr,
                                                    signer_id_buf.len,
                                                    &signer_id_buf.len,
                                                    sw_version_buf.ptr,
                                                    sw_version_buf.len,
                                                    &sw_version_buf.len,
                                                    &measurement_algo,
                                                    sw_type_buf.ptr,
                                                    sw_type_buf.len,
                                                    &sw_type_buf.len,
                                                    measurement_buf.ptr,
                                                    measurement_buf.len,
                                                    &measurement_buf.len,
                                                    &is_locked);
        if (status != PSA_SUCCESS) {
            continue;
        }

        measurement_cnt++;
        if (measurement_cnt == 1) {
            /* Open array which stores the boot measurements.
             * One measurement includes the measurement value of the
             * firmware and associated metadata.
             */
            QCBOREncode_OpenArray(&encode_context);
        }

        /* Get the string representation of the measurement algorithm. */
        status = get_firmware_measurement_description(
                                            (psa_algorithm_t)measurement_algo,
                                            &measurement_desc);
        if (status != PSA_SUCCESS) {
            /* The boot state cannot be completed. */
            return PSA_ERROR_GENERIC_ERROR;
        }

        status = encode_firmware_measurement(
                                    &encode_context,
                                    (struct q_useful_buf_c *)&signer_id_buf,
                                    (struct q_useful_buf_c *)&sw_version_buf,
                                    (struct q_useful_buf_c *)&sw_type_buf,
                                    &measurement_desc,
                                    (struct q_useful_buf_c *)&measurement_buf);
        if (status != PSA_SUCCESS) {
            return status;
        }
    }

    if (measurement_cnt != 0) {
        /* Close array which stores the firmware measurements. */
        QCBOREncode_CloseArray(&encode_context);
    }

    encode_error = QCBOREncode_Finish(&encode_context, &boot_state_buf_c);
    /* Check for any encoding errors. */
    if (encode_error == QCBOR_ERR_BUFFER_TOO_SMALL) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    } else if (encode_error != QCBOR_SUCCESS) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    *boot_state_len = boot_state_buf_c.len;

    return PSA_SUCCESS;
}

/**
 * \brief Derive a delegated attestation key using preprovisioned seed.
 *
 * \param[in]     ecc_curve    The type of the elliptic curve to which the
 *                             requested key belongs.
 * \param[in]     key_bits     The size of the requested key, in bits.
 * \param[in]     salt         Salt for key derivation.
 * \param[in]     salt_len     Size of the salt in bytes.
 * \param[out]    key_buf      Pointer to the buffer where the delegated
 *                             attestation key will be stored.
 * \param[in,out] key_buf_len  As an input it is the size of allocated buffer
 *                             for the key, in bytes. At return its value is
 *                             updated with the exact size of the derived
 *                             attestation key.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
static psa_status_t
derive_delegated_attestation_key(psa_ecc_family_t ecc_curve, uint32_t key_bits,
                                 uint8_t *salt, size_t salt_len,
                                 uint8_t *key_buf, size_t *key_buf_len)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    psa_status_t status;

    if (salt == NULL  || key_buf == NULL ||
        salt_len == 0 || key_buf_len == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = psa_destroy_key(dak_key_id);
    if (status != PSA_SUCCESS && status != PSA_ERROR_INVALID_HANDLE) {
        return status;
    }

    /* Set the key attributes for the delegated attestation key */
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(ecc_curve));
    psa_set_key_bits(&attributes, key_bits);

    status = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (status != PSA_SUCCESS) {
        return status;
    }

    /* Set up a key derivation operation with DAK seed  */
    status = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                          TFM_BUILTIN_KEY_ID_DAK_SEED);
    if (status != PSA_SUCCESS) {
        goto err_release_op;
    }

    /* Supply the secure boot state as input data to the key derivation */
    status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                            salt, salt_len);
    if (status != PSA_SUCCESS) {
        goto err_release_op;
    }

    /* Create the delegated attestation key from the key derivation operation */
    status = psa_key_derivation_output_key(&attributes, &op,
                                           &dak_key_id);
    if (status != PSA_SUCCESS) {
        goto err_release_op;
    }

    status = psa_export_key(dak_key_id,
                            key_buf, *key_buf_len, key_buf_len);
    if (status != PSA_SUCCESS) {
        goto err_release_key;
    }

    /* Free resources associated with the key derivation operation */
    return psa_key_derivation_abort(&op);

err_release_key:
    (void)psa_destroy_key(dak_key_id);

err_release_op:
    (void)psa_key_derivation_abort(&op);

    return PSA_ERROR_GENERIC_ERROR;
}

psa_status_t
delegated_attest_get_delegated_key(psa_ecc_family_t ecc_curve,
                                   uint32_t         key_bits,
                                   uint8_t         *key_buf,
                                   size_t           key_buf_size,
                                   size_t          *key_size,
                                   psa_algorithm_t  hash_algo)
{
    psa_status_t status;
    psa_hash_operation_t hash_op = psa_hash_operation_init();
    size_t boot_records_len = 0;
    size_t key_len;

    /* Check the hash algorithm (input) if it is valid and supported. */
    status = psa_hash_setup(&hash_op, hash_algo);
    (void)psa_hash_abort(&hash_op);
    if (status != PSA_SUCCESS) {
        return status;
    }

    boot_records_len = sizeof(boot_state_buffer);
    status = get_platform_boot_state(boot_state_buffer,
                                     &boot_records_len);
    if (status != PSA_SUCCESS) {
        return status;
    }

    key_len = key_buf_size;
    status = derive_delegated_attestation_key(
                                        ecc_curve, key_bits,
                                        boot_state_buffer, boot_records_len,
                                        key_buf, &key_len);
    if (status != PSA_SUCCESS) {
        return status;
    }

    *key_size = key_len;
    dak_requested = true;
    /* Storing the hash algorithm for later use. */
    dak_pub_hash_algo = hash_algo;

    return PSA_SUCCESS;
}

psa_status_t
delegated_attest_get_platform_token(const uint8_t *dak_pub_hash,
                                    size_t         dak_pub_hash_size,
                                    uint8_t       *token_buf,
                                    size_t         token_buf_size,
                                    size_t        *token_size)
{
    psa_status_t status;

    if (!dak_requested) {
        /* The platform attestation token cannot be created before a DAK has
         * been successfully requested.
         */
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Verify the hash of the public part of the DAK received as input */
    status = verify_dak_pub_hash(dak_pub_hash, dak_pub_hash_size);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_initial_attest_get_token(dak_pub_hash, dak_pub_hash_size,
                                          token_buf, token_buf_size,
                                          token_size);
    if (status != PSA_SUCCESS) {
        return status;
    }

    return PSA_SUCCESS;
}
