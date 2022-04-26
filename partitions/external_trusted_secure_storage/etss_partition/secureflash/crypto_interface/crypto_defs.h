/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef _CRYPTO_DEFS_H
#define _CRYPTO_DEFS_H

#include "psa/crypto.h"

/**
 * \brief Supported cipher types and modes
 *
 */
typedef enum {
    ALG_NONE,             // 000
 
    ALG_AES_CCM_128,      // 001
    ALG_AES_CCM_192,      // 002
    ALG_AES_CCM_256,      // 003
    ALG_AES_GCM_128,      // 004
    ALG_AES_GCM_192,      // 005
    ALG_AES_GCM_256,      // 006
    ALG_AES_ECB_128,      // 007
    ALG_AES_ECB_192,      // 008
    ALG_AES_ECB_256,      // 009
    ALG_AES_CBC_128,      // 010
    ALG_AES_CBC_192,      // 011
    ALG_AES_CBC_256,      // 012
    ALG_AES_OFB_128,      // 013
    ALG_AES_OFB_192,      // 014
    ALG_AES_OFB_256,      // 015
    ALG_AES_CTR_128,      // 016
    ALG_AES_CTR_192,      // 017
    ALG_AES_CTR_256,      // 018

    ALG_ECDSA_SECP192R1,  // 019
    ALG_ECDSA_SECP224R1,  // 020
    ALG_ECDSA_SECP256R1,  // 021
    ALG_ECDSA_SECP384R1,  // 022
    ALG_ECDSA_SECP521R1,  // 023
    ALG_ECDSA_BP256R1,    // 024
    ALG_ECDSA_BP384R1,    // 025
    ALG_ECDSA_BP512R1,    // 026
    ALG_ECDSA_CURVE25519, // 027
    ALG_ECDSA_SECP192K1,  // 028
    ALG_ECDSA_SECP224K1,  // 029
    ALG_ECDSA_SECP256K1,  // 030
    ALG_ECDSA_CURVE448,   // 031

    ALG_ECDH_SECP192R1,   // 032
    ALG_ECDH_SECP224R1,   // 033
    ALG_ECDH_SECP256R1,   // 034
    ALG_ECDH_SECP384R1,   // 035
    ALG_ECDH_SECP521R1,   // 036
    ALG_ECDH_BP256R1,     // 037
    ALG_ECDH_BP384R1,     // 038
    ALG_ECDH_BP512R1,     // 039
    ALG_ECDH_CURVE25519,  // 040
    ALG_ECDH_SECP192K1,   // 041
    ALG_ECDH_SECP256K1,   // 042
    ALG_ECDH_CURVE448,    // 043

    ALG_HMAC_SHA_1,       // 044
    ALG_HMAC_SHA_224,     // 045
    ALG_HMAC_SHA_256,     // 046
    ALG_HMAC_SHA_384,     // 047
    ALG_HMAC_SHA_512,     // 048
 
    ALG_HKDF_SHA_1,       // 049
    ALG_HKDF_SHA_224,     // 050
    ALG_HKDF_SHA_256,     // 051
    ALG_HKDF_SHA_384,     // 052
    ALG_HKDF_SHA_512,     // 053
} EncryptionAlgorithm;

/**
 * \brief Supported cryptographic operation properties
 *
 */
typedef enum {
    PROP_NO_SECURITY_OPERATION,   /*!< No security operation. */
    PROP_AUTHEN_TAG_DECRYPT_DATA, /*!< Authenticate tag and decrypt data */
    PROP_AUTHEN_TAG,              /*!< Authenticate tag only */
    PROP_DECRYPT_DATA,            /*!< Decrypt data only */
    PROP_ENCRYPT_TAG_DATA,        /*!< Encrypt data and generate authenticate tag */
    PROP_ENCRYPT_TAG,             /*!< Generate authenticate tag only */
    PROP_ENCRYPT_DATA,            /*!< Encrypt data only */
    PROP_HMAC,                    /*!< Hash-based MAC */
    PROP_HKDF,                    /*!< HKDF Extract-Expand */
    PROP_HKDF_EXTRACT,            /*!< HKDF Extract */
    PROP_HKDF_EXPAND,             /*!< HKDF Expand */
    PROP_SIGNATURE_SIGN,          /*!< Generate signature */
    PROP_SIGNATURE_VERIFY,        /*!< Verify signature */
} EncryptionProperty;

/**
 * \brief Cryptographic service error code
 *
 */
typedef enum {
    CRYPTO_SERVICE_ERROR_OK,
    CRYPTO_SERVICE_ERROR_AEAD_ENC,
    CRYPTO_SERVICE_ERROR_AEAD_DEC,
    CRYPTO_SERVICE_ERROR_CIPHER_ENC,
    CRYPTO_SERVICE_ERROR_CIPHER_DEC,
    CRYPTO_SERVICE_ERROR_HMAC,
    CRYPTO_SERVICE_ERROR_KDF,
    CRYPTO_SERVICE_ERROR_ALLOCATION,
    CRYPTO_SERVICE_ERROR_EXPORT_KEY,
    CRYPTO_SERVICE_ERROR_IMPORT_KEY,
    CRYPTO_SERVICE_ERROR_OPEN_KEY,
    CRYPTO_SERVICE_ERROR_CLOSE_KEY,
    CRYPTO_SERVICE_ERROR_DESTROY_KEY,
    CRYPTO_SERVICE_ERROR_GENERATE_RANDOM,
    CRYPTO_SERVICE_ERROR_NOT_SUPPORT
} CryptoServiceErrorCode;

/**
 * \brief Cryptographic keys' attributes
 *
 */
typedef struct {
    uint32_t type;     /*!< Key type: AES, DES, ECC public key,etc. */
    uint32_t lifetime; /*!< Key lifetime: persistent or transient */
    uint32_t usage;    /*!< Key usage: encryption, decryption, signature,
                            key derivation,etc. */
    uint32_t key_id;   /*!< Key identification */
    uint32_t alg;      /*!< Key supported cryptographic algorithm */
    uint32_t bits;     /*!< Key size in bits */
} key_attr_t;

/**
 * \brief Cryptographic operation indicator
 *
 */
typedef struct {
    union {
        /**
         * \struct aead
         *
         * \brief Structure containing AES-CCM/AES-GCM operation parameters.
         */
        struct {
            uint32_t key_id;
            uint8_t *iv;
            uint32_t iv_len;
            uint8_t *add;
            uint32_t add_len;
            uint8_t *plain_text;
            uint32_t plain_text_len;
            uint8_t *cipher_text;
            uint32_t cipher_text_len;
            uint8_t *tag;
            uint32_t tag_len;
        } aead;
        /**
         * \struct hkdf
         *
         * \brief Structure containing HKDF operation parameters.
         */
        struct {
            uint8_t *salt;
            uint32_t salt_len;
            uint8_t *ikm;
            uint32_t ikm_len;
            uint32_t ik_id;//input key id
            uint8_t *info;
            uint32_t info_len;
            uint8_t *okm;
            uint8_t *psk;
            uint32_t okm_len;
        } hkdf;//key derive
        /**
         * \struct cipher
         *
         * \brief Structure containing AES CBC/ECB operation parameters.
         */
        struct {
            uint32_t key_id;
            uint8_t *iv;
            uint32_t iv_len;
            uint8_t *plain_text;
            uint32_t plain_text_len;
            uint8_t *cipher_text;
            uint32_t cipher_text_len;
        } cipher;
        /**
         * \struct ecdsa
         *
         * \brief Structure containing ECDSA operation parameters.
         */
        struct {
            uint8_t *pub_key;
            uint32_t pub_key_len;
            uint8_t *pri_key;
            uint32_t pri_key_len;
            uint8_t *hash;
            uint8_t *signature;
            uint32_t signature_len;
            uint8_t *message;
            uint32_t message_len;
        } ecdsa;
        /**
         * \struct ecdh
         *
         * \brief Structure containing ECDH operation parameters.
         */
        struct {
            uint8_t *peer_pub_key;
            uint32_t peer_pub_key_len;
            uint32_t private_key_id;
            uint8_t *output;
            uint32_t output_len;
        } ecdh;
        /**
         * \struct hmac
         *
         * \brief Structure containing HMAC operation parameters.
         */
        struct {
            uint32_t key_id;
            uint8_t *input;
            uint32_t input_len;
            uint8_t *mac;
            uint32_t mac_len;
        } hmac;
    };
    EncryptionAlgorithm algorithm;
    EncryptionProperty property;
} crypto_indicator_t;


#define KEY_ATTR_INIT              {0, 0, 0, 0, 0, 0}
/* Key lifetime */
#define KEY_LIFETIME_VOLATILE      PSA_KEY_LIFETIME_VOLATILE
#define KEY_LIFETIME_PERSISTENT    PSA_KEY_LIFETIME_PERSISTENT
/* Key usage macros refer to psa crypto_values.h definitions*/
#define KEY_USAGE_EXPORT           PSA_KEY_USAGE_EXPORT
#define KEY_USAGE_DERIVE           PSA_KEY_USAGE_DERIVE
#define KEY_USAGE_ENCRYPT          PSA_KEY_USAGE_ENCRYPT
#define KEY_USAGE_DECRYPT          PSA_KEY_USAGE_DECRYPT
#define KEY_USAGE_SIGN_MSG         PSA_KEY_USAGE_SIGN_MESSAGE
#define KEY_USAGE_VERIFY_MSG       PSA_KEY_USAGE_VERIFY_MESSAGE
/* Key types */
#define KEY_TYPE_HMAC              PSA_KEY_TYPE_HMAC
#define KEY_TYPE_DERIVE            PSA_KEY_TYPE_DERIVE
#define KEY_TYPE_AES               PSA_KEY_TYPE_AES
/* Algorithms */
#define ALG_HMAC                   PSA_ALG_HMAC_BASE
#define ALG_ECB                    PSA_ALG_ECB_NO_PADDING
#define ALG_CCM                    PSA_ALG_CCM
#define ALG_GCM                    PSA_ALG_GCM
#define ALG_HKDF                   PSA_ALG_HKDF(PSA_ALG_SHA_256)

#endif /* _CRYPTO_DEFS_H */
