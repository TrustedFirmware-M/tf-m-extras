/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef _MX75_ARMOR_VENDOR_INFO_H
#define _MX75_ARMOR_VENDOR_INFO_H

#include "../../../crypto_interface/crypto_defs.h"
#include "../../../crypto_interface/crypto_interface.h"
#include "mx75_armor_provision_info.h"
#include "mxic_spi_nor_command.h"

#define ARMOR_MC_SIZE         4
#define ARMOR_MAC_SIZE        16
#define ARMOR_PUF_SIZE        32
#define ARMOR_KEY_SIZE        32
#define ARMOR_TRNG_SIZE       32
#define ARMOR_DATAZONE_NUM    16

#define ENCWR_PGM          0       /*!< Security program operation */
#define ENCWR_ERS          1       /*!< Security erase operation */

#define SIZE_4K_BYTES      0x1000  /*!< Security erase size equals 4K bytes */
#define SIZE_32K_BYTES     0x8000  /*!< Security erase size equals 32K bytes */
#define SIZE_64K_BYTES     0x10000 /*!< Security erase size equals 64K bytes */
#define BUFFER_SIZE        0x200   /*!< Temporary buffer size in bytes */
#define MAX_CCM_IV_LENGTH  13      /*!< Max size of AES-CCM input iv in bytes */
/**
 * MX75 ArmorFlash security items definition
 *
 */
typedef enum {
    CFG_ITEM,    /*!< Configuration */
    MC_ITEM,     /*!< Monotonic counters */
    KEY_ITEM,    /*!< Security keys */
    EXTRA_ITEM   /*!< Extra items */
}SecurityItem;

/**
 * \struct mx75_armor_crypto_service_t
 *
 * \brief Structure binding the crypto services needed by MX75 ArmorFlash and
 *        holding the crypto operation parameters.
 */
typedef struct {
    crypto_indicator_t indicator;
    int32_t (*aes_ccm_enc)(crypto_indicator_t *indicator);
    int32_t (*aes_ccm_dec)(crypto_indicator_t *indicator);
    int32_t (*aes_ecb_enc)(crypto_indicator_t *indicator);
    int32_t (*hkdf)(crypto_indicator_t *indicator);
    int32_t (*gen_key)(key_attr_t *key_attr, crypto_indicator_t *indicator);
    int32_t (*store_key)(key_attr_t *key_attr, const uint8_t *key,
                         uint32_t key_len, uint32_t *key_id);
    int32_t (*get_key)(uint32_t key_id, uint8_t *key, uint32_t key_len);
    int32_t (*open_key)(uint32_t key_id, uint32_t *key_handle);
    int32_t (*close_key)(uint32_t key_id);
    int32_t (*delete_key)(uint32_t key_id);
    int32_t (*check_algorithm_support)(int32_t alg);
} mx75_armor_crypto_service_t;

/**
 * \struct security_protocol_t
 *
 * \brief The format of MX75 ArmorFlash's security packets.
 */
typedef struct {
    uint16_t command;
    uint8_t command_len;
    uint32_t modifier;
    uint8_t modifier_len;
    uint8_t latency_len;
} security_protocol_t;

typedef struct {
    security_protocol_t reset_packet;
    security_protocol_t write_packet;
    security_protocol_t read_packet;
} mx75_armor_secure_protocol_t;

/**
 * \struct provision_info_t
 *
 * \brief The structure holding MX75 ArmorFlash's provisioning information.
 */
typedef struct {
    uint8_t is_provisioned:1; /*!< Whether ArmorFlash has been provisioned */
    key_info_t key_info;      /*!< ArmorFlash root key provisioning info */
    mx_app_info_t app_info;   /*!< ArmorFlash application provisioning info */
    lock_info_t lock_info;    /*!< ArmorFlash lock down info */
} provision_info_t;

/**
 * MX75 ArmorFlash supported security operations definition
 *
 */
typedef enum
{
    SECURITY_READ,        /*!< Security read */
    SECURITY_WRITE,       /*!< Security program */
    SECURITY_ERASE,       /*!< Security erase */
    MC_INCREASEMENT,      /*!< Increase a certain Monotonic counter */
    MC_READ,              /*!< Read a certain Monotonic counter */
    GENERATE_TRUE_RANDOM, /*!< Generate true random number */
    GENERATE_NONCE,       /*!< ArmoFLash generate nonce for cryptographic
                               operations */
    SET_NONCE,            /*!< Host set the nonce for cryptographic operations */
    IMPORT_KEY,           /*!< Update a certain security key */
    GENERATE_KEY,         /*!< Update a certain security key */
    DERIVE_KEY,           /*!< Update a certain security key */
    READ_PUF,             /*!< Read PUF generated secret values */
    CONFIRM_NONCE,        /*!< Nonce confirmation */
    GET_CFG,              /*!< Read configuration information */
    LOCK_DOWN             /*!< Lock down */
} mx75_armor_security_ops_t;

/**
 * \struct mx75_armor_security_ops_params_t
 *
 * \brief The structure holding MX75 ArmorFlash security operations' parameters.
 */
typedef struct {
    uint8_t *in_data;              /*!< Pointer to current security operation
                                        input data */
    uint32_t in_size;              /*!< Input data size in bytes */
    uint8_t *out_data;             /*!< Pointer to current security operation
                                        output data */
    uint32_t out_size;             /*!< Output data size in bytes */
    uint32_t addr;                 /*!< The access address of current
                                        security operation */
    uint8_t linked_mc_id;          /*!< Current security operation linked
                                        monotonic counter id */
    uint8_t *add;                  /*!< Pointer to the additional authentication
                                        data of current security operation */
    uint8_t add_len;               /*!< Additional authentication data size
                                        in bytes */
    uint8_t iv[MAX_CCM_IV_LENGTH]; /*!< Buffer holding the iv of current
                                        security operation */
    uint8_t iv_len;                /*!< IV size in bytes */
    uint32_t crypto_key_id;        /*!< Current security operation linked
                                        crypto service key id */
    mx75_armor_security_ops_t ops; /*!< Security operation */
} mx75_armor_security_ops_params_t;

/**
 * \struct mx75_armor_vendor_context_t
 *
 * \brief The structure holding MX75 ArmorFlash specific context.
 */
typedef struct {
    mx75_armor_crypto_service_t crypto_service; /*!< Crypto services needed by
                                                     MX75 ArmorFlash */
    mx75_armor_secure_protocol_t protocol;      /*!< MX75 ArmorFlash security
                                                     protocols */
    provision_info_t provision_info;            /*!< MX75 ArmorFlash
                                                     provisioning information */
    mxic_spi_nor_context_t *mxic_nor_ctx;       /*!< Underlying spi nor flash
                                                     context */
} mx75_armor_vendor_context_t;

#endif /* _MX75_ARMOR_VENDOR_INFO_H */
