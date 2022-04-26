/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef _CRYPTO_INTERFACE_H_
#define _CRYPTO_INTERFACE_H_

#include "crypto_defs.h"

/**
 * \file crypto_interface.h
 *
 * \brief This file lists crypto service interfaces.
 * \details Here crypto service interfaces call tf-m crypto services to
 *          implement key management, AEAD encryption/decryption,
 *          symmetric cipher encryption/decryption, etc.
 */


/** \defgroup crypto_if crypto service interface
 * @{
 */

/**
 * \brief Derive a key.
 *
 * \param[in] key_attr  The attribute of derived key
 * \param[in] indicator The cryptographic indicator of key derivation operation
 * \return CRYPTO_SERVICE_ERROR_OK if successful,
 *         or CRYPTO_SERVICE_ERROR_KDF if failed
 */
int32_t crypto_if_derive_key(key_attr_t *key_attr,
                             crypto_indicator_t *indicator);
/**
 * \brief Import a key into crypto service.
 *
 * \param[in] key_attr       The attribute of derived key
 * \param[in] key            The buffer containing key data
 * \param[in] key_len        The length of key data in bytes
 * \param[out] crypto_key_id The key identification
 * \return CRYPTO_SERVICE_ERROR_OK if successful,
 *         or CRYPTO_SERVICE_ERROR_XX if failed
 */
int32_t crypto_if_import_key(key_attr_t *key_attr, const uint8_t *key,
                             uint32_t key_len, uint32_t *crypto_key_id);
/**
 * \brief Export a key from crypto service.
 *
 * \param[in]  key_id        The identification of key to export
 * \param[out] key           The buffer where the key data is to be written
 * \param[in]  key_len       The length of key data in bytes

 * \return CRYPTO_SERVICE_ERROR_OK if successful,
 *         or CRYPTO_SERVICE_ERROR_XX if failed
 */
int32_t crypto_if_export_key(uint32_t key_id, uint8_t *key, uint32_t key_len);
/**
 * \brief Open a key.
 *
 * \param[in]  key_id        The identification of key to open
 * \param[out] key_handle    Pointer to the handle of the key
 * \return CRYPTO_SERVICE_ERROR_OK if successful,
 *         or CRYPTO_SERVICE_ERROR_XX if failed
 */
int32_t crypto_if_open_key(uint32_t key_id, uint32_t *key_handle);
/**
 * \brief Close a key.
 *
 * \param[in] key_id         The identification of key to close

 * \return CRYPTO_SERVICE_ERROR_OK if successful,
 *         or CRYPTO_SERVICE_ERROR_XX if failed
 */
int32_t crypto_if_close_key(uint32_t key_id);
/**
 * \brief Destroy a key.
 *
 * \param[in] key_id         The identification of key to destroy

 * \return CRYPTO_SERVICE_ERROR_OK if successful,
 *         or CRYPTO_SERVICE_ERROR_XX if failed
 */
int32_t crypto_if_destroy_key(uint32_t key_id);

/* aead */

/**
 * \brief AEAD(AES-CCM/AES-GCM) encryption.
 *
 * \param[in] indicator      The structure holding AEAD encryption parameters

 * \return CRYPTO_SERVICE_ERROR_OK if successful,
 *         or CRYPTO_SERVICE_ERROR_XX if failed
 */
int32_t crypto_if_aead_encrypt(crypto_indicator_t *indicator);
/**
 * \brief AEAD(AES-CCM/AES-GCM) decryption.
 *
 * \param[in] indicator      The structure holding AEAD decryption parameters

 * \return CRYPTO_SERVICE_ERROR_OK if successful,
 *         or CRYPTO_SERVICE_ERROR_XX if failed
 */
int32_t crypto_if_aead_decrypt(crypto_indicator_t *indicator);

/* cipher */

/**
 * \brief Symmetric ciphers encryption.
 *
 * \param[in] indicator       The structure holding AES-CBC/AES-ECB
 *                            encryption parameters
 * \return CRYPTO_SERVICE_ERROR_OK if successful,
 *         or CRYPTO_SERVICE_ERROR_XX if failed
 */
int32_t crypto_if_cipher_encrypt(crypto_indicator_t *indicator);
/**
 * \brief Symmetric ciphers decryption.
 *
 * \param[in] indicator       The structure holding AES-CBC/AES-ECB
 *                            decryption parameters
 * \return CRYPTO_SERVICE_ERROR_OK if successful,
 *         or CRYPTO_SERVICE_ERROR_XX if failed
 */
int32_t crypto_if_cipher_decrypt(crypto_indicator_t *indicator);


/* mac */

/**
 * \brief Verify mac.
 *
 * \param[in] indicator       The structure holding mac verification parameters

 * \return CRYPTO_SERVICE_ERROR_OK if successful,
 *         or CRYPTO_SERVICE_ERROR_XX if failed
 */
int32_t crypto_if_verify_mac(crypto_indicator_t *indicator);
/**
 * \brief Generate mac.
 *
 * \param[in] indicator       The structure holding mac calculation parameters

 * \return CRYPTO_SERVICE_ERROR_OK if successful,
 *         or CRYPTO_SERVICE_ERROR_XX if failed
 */
int32_t crypto_if_compute_mac(crypto_indicator_t *indicator);


/* hkdf */

/**
 * \brief Derive a key based on hkdf.
 *
 * \param[in] indicator        The structure holding hkdf parameters

 * \return CRYPTO_SERVICE_ERROR_OK if successful,
 *         or CRYPTO_SERVICE_ERROR_XX if failed
 */
int32_t crypto_if_hkdf(crypto_indicator_t *indicator);


/* trng */

/* \brief Generate random bytes.
*
* \param[out] output           Output buffer holding the generated data
* \param[out] output_size      Size of output buffer in bytes
*
* \return CRYPTO_SERVICE_ERROR_OK if successful,
*         or CRYPTO_SERVICE_ERROR_XX if failed
*/
int32_t crypto_if_generate_random(uint8_t *output, size_t output_size);

/**@}*/

/* \brief Check whether a cipher algorithm is supported.
*
* \param[in] alg               Input cipher algorithm
*/
int32_t crypto_if_check_algorithm_support(int32_t alg);
#endif /* _CRYPTO_INTERFACE_H_ */
