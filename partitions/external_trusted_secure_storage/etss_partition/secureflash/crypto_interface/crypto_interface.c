/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <string.h>
#include <stddef.h>
#include "crypto_interface.h"
#include "tfm_memory_utils.h"

#define KEY_HANDLE_NOT_LOADED 0

#define AEAD_TAG_LEN                              16
#define AEAD_ENCRYPT_OUTPUT_SIZE(plaintext_len)   (plaintext_len + AEAD_TAG_LEN)
#define CRYPTO_AEAD_BUF_LEN                   (CRYPTO_ASSET_SIZE + AEAD_TAG_LEN)


/* Run a PSA function and bail out if it fails. */
#define PSA_CHECK( expr )                                       \
    do                                                          \
    {                                                           \
        status = ( expr );                                      \
        if( status != PSA_SUCCESS )                             \
        {                                                       \
            goto exit;                                          \
        }                                                       \
    }                                                           \
    while( 0 )

/*
 * Currently only hkdf is supported
 */
int32_t crypto_if_derive_key(key_attr_t *key_attr, crypto_indicator_t *indicator)
{
    /* set key attributes */
    psa_status_t status;
    psa_key_id_t crypto_key;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_derivation_operation_t operation = PSA_KEY_DERIVATION_OPERATION_INIT;

    psa_set_key_usage_flags(&attributes, key_attr->usage);
    psa_set_key_algorithm(&attributes, key_attr->alg);
    psa_set_key_type(&attributes, key_attr->type);
    psa_set_key_bits(&attributes, key_attr->bits);

    /* Start deriving keys from the provisioning key data. */
    if (indicator->algorithm == ALG_HKDF_SHA_256) {
        PSA_CHECK(psa_key_derivation_setup(&operation, PSA_ALG_HKDF(PSA_ALG_SHA_256)));
        PSA_CHECK(psa_key_derivation_input_bytes(&operation,
                                                 PSA_KEY_DERIVATION_INPUT_SALT,
                                                 indicator->hkdf.salt,
                                                 indicator->hkdf.salt_len));
        PSA_CHECK(psa_key_derivation_input_key(&operation,
                                               PSA_KEY_DERIVATION_INPUT_SECRET,
                                               indicator->hkdf.ik_id));
        PSA_CHECK(psa_key_derivation_input_bytes(&operation,
                                                 PSA_KEY_DERIVATION_INPUT_INFO,
                                                 indicator->hkdf.info,
                                                 indicator->hkdf.info_len));
        PSA_CHECK(psa_key_derivation_output_key(&attributes, &operation,
                                                &crypto_key));
        /* volatile key */
        if (!key_attr->lifetime) {
            key_attr->key_id = crypto_key;
        }
    } else {
        /* TODO */
        return CRYPTO_SERVICE_ERROR_NOT_SUPPORT;
    }
exit:
    psa_key_derivation_abort(&operation);
    if (status != PSA_SUCCESS) {
        psa_destroy_key(crypto_key);
        return CRYPTO_SERVICE_ERROR_KDF;
    }
    return CRYPTO_SERVICE_ERROR_OK;
}

int32_t crypto_if_export_key(uint32_t key_id, uint8_t *key, uint32_t key_len)
{
    psa_status_t status;
    size_t exported_data_size = 0;
    status = psa_export_key(key_id, key, key_len, &exported_data_size);
    if ((status != PSA_SUCCESS) || (exported_data_size != key_len)) {
        return CRYPTO_SERVICE_ERROR_EXPORT_KEY;
    }
    return CRYPTO_SERVICE_ERROR_OK;
}

int32_t crypto_if_import_key(key_attr_t *key_attr, const uint8_t *key,
                             uint32_t key_len, uint32_t *crypto_key_id)
{
    psa_status_t status;
    psa_key_id_t key_id = KEY_HANDLE_NOT_LOADED;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_usage_flags(&attributes, key_attr->usage);
    psa_set_key_algorithm(&attributes, key_attr->alg);
    psa_set_key_type(&attributes, key_attr->type);
    psa_set_key_bits(&attributes, key_attr->bits);
    if (key_attr->lifetime == KEY_LIFETIME_PERSISTENT) {
        psa_set_key_id(&attributes, key_attr->key_id);
    }
    status = psa_import_key(&attributes, key, key_len, &key_id);
    if (status != PSA_SUCCESS) {
        return CRYPTO_SERVICE_ERROR_IMPORT_KEY;
    }
    *crypto_key_id = key_id;
    return CRYPTO_SERVICE_ERROR_OK;
}

int32_t crypto_if_open_key(uint32_t key_id, uint32_t *key_handle)
{
    psa_status_t status;

    status = psa_open_key(key_id, key_handle);
    if (status != PSA_SUCCESS) {
        return CRYPTO_SERVICE_ERROR_OPEN_KEY;
    }
    return CRYPTO_SERVICE_ERROR_OK;
}

int32_t crypto_if_close_key(uint32_t key_id)
{
    psa_status_t status;

    status = psa_close_key(key_id);
    if (status != PSA_SUCCESS) {
        return CRYPTO_SERVICE_ERROR_CLOSE_KEY;
    }
    return CRYPTO_SERVICE_ERROR_OK;
}

int32_t crypto_if_destroy_key(uint32_t key_id)
{
    psa_status_t status;

    /* Destroy the transient key */
    status = psa_destroy_key(key_id);
    if (status != PSA_SUCCESS) {
        return CRYPTO_SERVICE_ERROR_DESTROY_KEY;
    }
    return CRYPTO_SERVICE_ERROR_OK;
}

/* AEAD */
int32_t crypto_if_aead_encrypt(crypto_indicator_t *indicator)
{
    psa_status_t status;
    size_t out_len = 0;
    uint8_t output_buf[CRYPTO_AEAD_BUF_LEN] = {0};
    size_t output_buf_size =
                      AEAD_ENCRYPT_OUTPUT_SIZE(indicator->aead.plain_text_len);
    switch (indicator->algorithm) {
    case ALG_AES_CCM_128:
    case ALG_AES_CCM_256:
        status = psa_aead_encrypt(indicator->aead.key_id, PSA_ALG_CCM,
                                  indicator->aead.iv, indicator->aead.iv_len,
                                  indicator->aead.add, indicator->aead.add_len,
                                  indicator->aead.plain_text,
                                  indicator->aead.plain_text_len,
                                  output_buf, output_buf_size, &out_len);
        if (out_len > CRYPTO_AEAD_BUF_LEN) {
            status = CRYPTO_SERVICE_ERROR_ALLOCATION;
        }
        break;
    case ALG_AES_GCM_128:
    case ALG_AES_GCM_256:
        status = psa_aead_encrypt(indicator->aead.key_id, PSA_ALG_GCM,
                                  indicator->aead.iv, indicator->aead.iv_len,
                                  indicator->aead.add, indicator->aead.add_len,
                                  indicator->aead.plain_text,
                                  indicator->aead.plain_text_len,
                                  output_buf, output_buf_size, &out_len);
        if (out_len > CRYPTO_AEAD_BUF_LEN) {
            status = CRYPTO_SERVICE_ERROR_ALLOCATION;
        }
        break;
    default:
        status = CRYPTO_SERVICE_ERROR_NOT_SUPPORT;
        break;
    }
    if (status != PSA_SUCCESS) {
        return CRYPTO_SERVICE_ERROR_AEAD_ENC;
    }
    /* Authentication tag is appended to the encrypted data */
    tfm_memcpy(indicator->aead.cipher_text, output_buf,
               indicator->aead.cipher_text_len);
    tfm_memcpy(indicator->aead.tag,
               output_buf + indicator->aead.cipher_text_len,
               indicator->aead.tag_len);
    return CRYPTO_SERVICE_ERROR_OK;
}

int32_t crypto_if_aead_decrypt(crypto_indicator_t *indicator)
{
    psa_status_t status;
    size_t out_len = 0;
    uint8_t input_buf[CRYPTO_AEAD_BUF_LEN] = {0};
    size_t input_buf_size =
                     indicator->aead.cipher_text_len + indicator->aead.tag_len;
    if (input_buf_size > CRYPTO_AEAD_BUF_LEN) {
        return CRYPTO_SERVICE_ERROR_ALLOCATION;
    }
    /* Copy the cipher text and tag into the crypto buffer */
    tfm_memcpy(input_buf, indicator->aead.cipher_text, indicator->aead.cipher_text_len);
    tfm_memcpy((input_buf + indicator->aead.cipher_text_len),
               indicator->aead.tag, indicator->aead.tag_len);
    switch (indicator->algorithm) {
    case ALG_AES_CCM_128:
    case ALG_AES_CCM_256:
        status = psa_aead_decrypt(indicator->aead.key_id, PSA_ALG_CCM,
                                  indicator->aead.iv, indicator->aead.iv_len,
                                  indicator->aead.add, indicator->aead.add_len,
                                  input_buf, input_buf_size,
                                  indicator->aead.plain_text,
                                  indicator->aead.plain_text_len, &out_len);
        break;
    case ALG_AES_GCM_128:
    case ALG_AES_GCM_256:
        status = psa_aead_decrypt(indicator->aead.key_id, PSA_ALG_GCM,
                                  indicator->aead.iv, indicator->aead.iv_len,
                                  indicator->aead.add, indicator->aead.add_len,
                                  input_buf, input_buf_size,
                                  indicator->aead.plain_text,
                                  indicator->aead.plain_text_len, &out_len);
        break;
    default:
        status = CRYPTO_SERVICE_ERROR_NOT_SUPPORT;
        break;
    }
    if (status != PSA_SUCCESS) {
        return CRYPTO_SERVICE_ERROR_AEAD_DEC;
    }
    return CRYPTO_SERVICE_ERROR_OK;
}

/* cipher */
int32_t crypto_if_cipher_encrypt(crypto_indicator_t *indicator)
{
    psa_status_t status;
    size_t out_len;
    /* implement one-shot cipher */
    switch (indicator->algorithm) {
    case ALG_AES_ECB_256:
        status = psa_cipher_encrypt(indicator->cipher.key_id,
                                    PSA_ALG_ECB_NO_PADDING,
                                    indicator->cipher.plain_text,
                                    indicator->cipher.plain_text_len,
                                    indicator->cipher.cipher_text,
                                    indicator->cipher.cipher_text_len, &out_len);
        if (status != PSA_SUCCESS) {
            return CRYPTO_SERVICE_ERROR_CIPHER_ENC;
        }
        return CRYPTO_SERVICE_ERROR_OK;
    case ALG_AES_CBC_256:
        status = psa_cipher_encrypt(indicator->cipher.key_id,
                                    PSA_ALG_CBC_NO_PADDING,
                                    indicator->cipher.plain_text,
                                    indicator->cipher.plain_text_len,
                                    indicator->cipher.cipher_text,
                                    indicator->cipher.cipher_text_len, &out_len);
        if (status != PSA_SUCCESS) {
            return CRYPTO_SERVICE_ERROR_CIPHER_ENC;
        }
        return CRYPTO_SERVICE_ERROR_OK;
    default:
        return CRYPTO_SERVICE_ERROR_NOT_SUPPORT;
    }
}

int32_t crypto_if_cipher_decrypt(crypto_indicator_t *indicator)
{
    psa_status_t status;
    size_t out_len;
    switch (indicator->algorithm) {
    case ALG_AES_ECB_256:
        status = psa_cipher_decrypt(indicator->cipher.key_id,
                                    PSA_ALG_ECB_NO_PADDING,
                                    indicator->cipher.cipher_text,
                                    indicator->cipher.cipher_text_len,
                                    indicator->cipher.plain_text,
                                    indicator->cipher.plain_text_len, &out_len);
        if (status != PSA_SUCCESS) {
            return CRYPTO_SERVICE_ERROR_CIPHER_DEC;
        }
        return CRYPTO_SERVICE_ERROR_OK;
    case ALG_AES_CBC_256:
        status = psa_cipher_decrypt(indicator->cipher.key_id,
                                    PSA_ALG_CBC_NO_PADDING,
                                    indicator->cipher.cipher_text,
                                    indicator->cipher.cipher_text_len,
                                    indicator->cipher.plain_text,
                                    indicator->cipher.plain_text_len, &out_len);
        if (status != PSA_SUCCESS) {
            return CRYPTO_SERVICE_ERROR_CIPHER_DEC;
        }
        return CRYPTO_SERVICE_ERROR_OK;
     default:
        return CRYPTO_SERVICE_ERROR_NOT_SUPPORT;
    }
}

/* MAC */
int32_t crypto_if_verify_mac(crypto_indicator_t *indicator)
{
    /* TODO */
    return CRYPTO_SERVICE_ERROR_OK;
}

int32_t crypto_if_compute_mac(crypto_indicator_t *indicator)
{
    /* TODO */
    return CRYPTO_SERVICE_ERROR_OK;
}

/* HKDF */
int32_t crypto_if_hkdf(crypto_indicator_t *indicator)
{
    /* TODO */
    return CRYPTO_SERVICE_ERROR_OK;
}

/* generate random number */
int32_t crypto_if_generate_random(uint8_t *output, size_t output_size)
{
    psa_status_t status;
    status = psa_generate_random(output, output_size);
    if (status != PSA_SUCCESS) {
        return CRYPTO_SERVICE_ERROR_GENERATE_RANDOM;
    }
    return CRYPTO_SERVICE_ERROR_OK;
}

int32_t crypto_if_check_algorithm_support(int32_t alg)
{
    /* TODO */
    return CRYPTO_SERVICE_ERROR_OK;
}
