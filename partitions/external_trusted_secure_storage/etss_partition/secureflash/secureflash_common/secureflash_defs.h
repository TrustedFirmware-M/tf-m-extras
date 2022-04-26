/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef _SECUREFLASH_COMMON_DEFS_H
#define _SECUREFLASH_COMMON_DEFS_H

#include "secureflash_error.h"
#include "../crypto_interface/crypto_defs.h"
#include "SFDP.h"

#ifdef SECUREFLASH_DEBUG
#include <stdio.h>
#define SF_COMMON_WARN_PR printf
#define SF_COMMON_DBG_PR printf
#define SF_COMMON_DBG0_PR printf
#define SF_COMMON_INFO_PR printf
#define SF_COMMON_ERR_PR printf
#define SF_COMMON_TMP_PR printf
#else
#define SF_COMMON_WARN_PR
#define SF_COMMON_DBG_PR
#define SF_COMMON_DBG0_PR
#define SF_COMMON_INFO_PR
#define SF_COMMON_ERR_PR
#define SF_COMMON_TMP_PR
#endif

#define CHIPER_SUITE_MAX_NUM 4
#define SESSION_INFO_MAX_NUM 4

/**
 * \addtogroup secureflash_common
 * \{
 */

/*!
 * \struct security_feature_t
 *
 * \brief Structure to store the security features of secure Flash.
 */
typedef struct {
    uint32_t security_storage: 1, /*!< Support security storage of data */
             RPMC: 1,             /*!< Support replay protection
                                       monotonic counter */
             UID: 1,              /*!< Support unique id */
             RNG: 1,              /*!< Support random number generator */
             PUF: 1,              /*!< Support physical unclonable function */
             Reserved: 27;        /*!< Reserved */
}security_feature_t;

/*!
 * \struct cipher_suite_t
 *
 * \brief Structure to store the cipher suites of secure Flash.
 */
typedef struct {
    uint32_t key_exchange_alg: 8, /*!< Key exchange algorithm */
             key_derive_alg: 8,   /*!< Key derivation algorithm */
             encryption_alg: 8,   /*!< Encryption algorithm */
             signature_alg: 8;    /*!< Signature algorithm */
} cipher_suite_t;

/*!
 * \struct key_size_t
 *
 * \brief Structure to store secure Flash various keys' size.
 */
typedef struct {
    uint32_t session_key_size: 16,
             private_key_size: 16;
    uint32_t public_key_size: 16,
             preshare_key_size: 16;
    uint32_t salt_key_size: 16,
             root_key_size: 16;
    uint32_t rpmc_root_key_size: 16,
             rpmc_hmac_key_size: 16;
} key_size_t;

/*!
 * \struct architecture_t
 *
 * \brief Structure to store secure Flash architecture.
 */
typedef struct {
    uint32_t secure_read_size;              /*!< Security read size in bytes */
    uint32_t secure_program_size;           /*!< Security program size in bytes */
    uint32_t secure_erase_size[4];          /*!< Security erase size in bytes */
    uint32_t regions_min_secure_erase_size; /*!< Minimum security erase size in
                                                 bytes */
    uint32_t secure_zone_number;            /*!< Secure data zone number */
    uint32_t secure_zone_size;              /*!< Individual data zone size */
    uint32_t secure_zone_total_size;        /*!< Whole data zones size */
} architecture_t;

/*!
 * \struct flash_profile_t
 *
 * \brief Structure to store secure Flash profile.
 */
typedef struct {
    security_feature_t security_feature; /*!< Secure Flash security features */
    cipher_suite_t cipher_suite;         /*!< Secure Flash cipher suites */
    key_size_t key_size;                 /*!< Secure Flash keys size */
    architecture_t architecture;         /*!< Secure Flash architecture */
} flash_profile_t;

typedef struct session_info_t session_info_t;

/*!
 * \struct session_info_t
 *
 * \brief Structure to store secure Flash session information.
 */
struct session_info_t{
    uint32_t key_id;         /*!< Root key id */
    uint32_t session_key_id; /*!< Session key id */
    uint32_t session_id;     /*!< Session id */
};

typedef struct sf_ctx sf_ctx_t;

/**
 * \struct sf_ctx
 *
 * \brief Structure containing secure Flash operation parameters and
 *        information.
 */
struct sf_ctx {
    /*!
     * \brief Secure Flash name.
     */
    const char *name;
    /*!
     * \struct vendor_op
     *
     * \brief Structure containing vendor specific secure Flash operation
     *        parameters.
     */
    struct {
    /*!
     * \brief Vendor specific operation name.
     */
        const char *name;
        /**
         * \brief Parse and store provision data.
         *
         * \param[in] sf_ctx           The specific secure Flash context
         * \param[in] provision_data   Pointer to the provision data
         * \return SECUREFLASH_ERROR_OK if successful,
         *         or a specific SECUREFLASH_ERROR_XXX error code
         */
        int32_t (*write_provision)(sf_ctx_t *sf_ctx, void *provision_data);
        /**
         * \brief Read provision data.
         *
         * \param[in] sf_ctx           The specific secure Flash context
         * \param[out] provision_data  Pointer to the provision data
         * \return SECUREFLASH_ERROR_OK if successful,
         *         or a specific SECUREFLASH_ERROR_XXX error code
         */
        int32_t (*read_provision)(sf_ctx_t *sf_ctx, void *provision_data);
        /**
         * \brief Lock down information provisioning.
         *
         * \param[in] sf_ctx           The specific secure Flash context
         * \param[in] provision_data   Pointer to the provision data
         * \return SECUREFLASH_ERROR_OK if successful,
         *         or a specific SECUREFLASH_ERROR_XXX error code
         */
        int32_t (*lock_provision)(sf_ctx_t *sf_ctx, void *provision_data);
        /**
         * \brief Write RPMC root key.
         *
         * \param[in] sf_ctx           The specific secure Flash context
         * \param[in] mc_addr          Target monotonic counter
         * \param[in] root_key         Pointer to root key value
         *
         * \return SECUREFLASH_ERROR_OK if successful,
         *         or a specific SECUREFLASH_ERROR_XXX error code
         */
        int32_t (*rpmc_write_root_key)(sf_ctx_t *sf_ctx, uint8_t mc_addr,
                                       uint8_t *root_key);
        /**
         * \brief Initialize the secure Flash device.
         *
         * \param[in] sf_ctx           The specific secure Flash context
         *
         * \return SECUREFLASH_ERROR_OK if successful,
         *         or a specific SECUREFLASH_ERROR_XXX error code
         */
        int32_t (*init)(sf_ctx_t *sf_ctx);
        /**
         * \brief Deinitialize the secure Flash device.
         *
         * \param[in] sf_ctx           The specific secure Flash context
         *
         * \return SECUREFLASH_ERROR_OK if successful,
         *         or a specific SECUREFLASH_ERROR_XXX error code
         */
        int32_t (*deinit)(sf_ctx_t *sf_ctx);
        /**
         * \brief Create a new session based on key_id.
         *
         * \param[in]  sf_ctx          The specific secure Flash context
         * \param[in]  key_id          Input key id used to derive session key
         * \param[out] session_key_id  Pointer to derived session key id
         * \param[out] session_id      Generated session id
         * \return SECUREFLASH_ERROR_OK if successful,
         *         or a specific SECUREFLASH_ERROR_XXX error code
         */
        int32_t (*create_session)(sf_ctx_t *sf_ctx, uint32_t key_id,
                                  uint32_t *session_key_id,
                                  uint32_t *session_id);
        /**
         * \brief Close a session specified by session_id.
         *
         * \param[in] sf_ctx           The specific secure Flash context
         * \param[in] session_id       The id of a session to be closed
         * \return SECUREFLASH_ERROR_OK if successful,
         *         or a specific SECUREFLASH_ERROR_XXX error code
         */
        int32_t (*close_session)(sf_ctx_t *sf_ctx, uint32_t session_id);
        /**
         * \brief Update the HMAC key of a monotonic counter.
         *
         * \param[in] sf_ctx           The specific secure Flash context
         * \param[in] mc_addr          Target monotonic counter
         * \param[in] key_id           The root key id
         * \return SECUREFLASH_ERROR_OK if successful,
         *         or a specific SECUREFLASH_ERROR_XXX error code
         */
        int32_t (*rpmc_update_hmac_key)(sf_ctx_t *sf_ctx, uint8_t mc_addr,
                                        uint32_t key_id);
        /**
         * \brief Read data from secure Flash with a secure session specified
         *        by session_id.
         *
         * \param[in]  sf_ctx          The specific secure Flash context
         * \param[out] buffer          Pointer to a buffer storing data read
         *                             from secure Flash
         * \param[in] addr             Data address
         * \param[in] size             Number of data items to read in bytes
         * \param[in] session_id       The session id
         * \return SECUREFLASH_ERROR_OK if successful,
         *         or a specific SECUREFLASH_ERROR_XXX error code
         */
        int32_t (*secure_read)(sf_ctx_t *sf_ctx, uint8_t *buffer, size_t addr,
                               size_t size, uint32_t session_id);
        /**
         * \brief Program data to secure Flash with a secure session specified
         *        by session_id.
         *
         * \param[in] sf_ctx           The specific secure Flash context
         * \param[in] buffer           Pointer to a buffer containing data to be
         *                             programmed to secure Flash
         * \param[in] addr             Target address
         * \param[in] size             Number of data items to program in bytes
         * \param[in] session_id       The session id
         * \return SECUREFLASH_ERROR_OK if successful,
         *         or a specific SECUREFLASH_ERROR_XXX error code
         */
        int32_t (*secure_program)(sf_ctx_t *sf_ctx, const uint8_t *buffer,
                                  size_t addr, size_t size,
                                  uint32_t session_id);
        /**
         * \brief Erase secure Flash with a secure session specified
         *        by session_id.
         *
         * \param[in] sf_ctx           The specific secure Flash context
         * \param[in] addr             Address of sector/block to be erased
         * \param[in] size             Size to be erased in bytes
         * \param[in] session_id       The session id
         * \return SECUREFLASH_ERROR_OK if successful,
         *         or a specific SECUREFLASH_ERROR_XXX error code
         */
        int32_t (*secure_erase)(sf_ctx_t *sf_ctx, size_t addr, size_t size,
                                uint32_t session_id);
        /**
         * \brief Get an unique value based on secure Flash Physical
         *        Unclonable Function.
         *
         * \param[in]  sf_ctx           The specific secure Flash context
         * \param[out] puf              Pointer to a buffer storing data to be
         *                              derived
         * \param[in]  size             Size of the buffer
         * \param[out] actual_size      The actual size of derived value in bytes
         * \param[in]  input_param      Input buffer contain some data
         * \param[in]  input_param_size The size of input_data in bytes
         *
         * \return SECUREFLASH_ERROR_OK if successful,
         *         or a specific SECUREFLASH_ERROR_XXX error code
         */
        int32_t (*get_puf)(sf_ctx_t *sf_ctx, uint8_t *puf, uint8_t size,
                           uint8_t *actual_size, uint8_t *input_param,
                           uint8_t input_param_size);
        /**
         * \brief Get the unique id of secure Flash.
         *
         * \param[in]  sf_ctx           The specific secure Flash context
         * \param[out] uid              Pointer to buffer storing derived
         *                              unique id
         * \param[in]  size             Size of the buffer
         * \param[out] actual_size      The actual size of derived unique id
         *                              in bytes
         *
         * \return SECUREFLASH_ERROR_OK if successful,
         *         or a specific SECUREFLASH_ERROR_XXX error code
         */
        int32_t (*get_uid)(sf_ctx_t *sf_ctx, uint8_t *uid, uint8_t size,
                           uint8_t *actual_size);
        /**
         * \brief Get a true random number from secure Flash True
         *        Random Number Generator.
         *
         * \param[in]  sf_ctx           The specific secure Flash context
         * \param[out] random           Pointer to buffer storing derived
         *                              random number
         * \param[in]  size             Size of buffer
         * \param[out] actual_size      The actual size of derived random
         *                              number in bytes
         *
         * \return SECUREFLASH_ERROR_OK if successful,
         *         or a specific SECUREFLASH_ERROR_XXX error code
         */
        int32_t (*get_trng)(sf_ctx_t *sf_ctx, uint8_t *random, uint8_t size,
                            uint8_t *actual_size);
        /**
         * \brief Read the given monotonic counter of secure Flash.
         *
         * \param[in]  sf_ctx           The specific secure Flash context
         * \param[in]  mc_addr          Target monotonic counter address
         * \param[out] mc               Pointer to buffer storing counter value
         * \param[in]  size             Size of buffer in bytes
         * \param[out] actual_size      The actual size of counter value
         *                              in bytes
         *
         * \return SECUREFLASH_ERROR_OK if successful,
         *         or a specific SECUREFLASH_ERROR_XXX error code
         */
        int32_t (*get_mc)(sf_ctx_t *sf_ctx, uint8_t mc_addr, uint8_t *mc,
                          uint8_t size, uint8_t *actual_size);
        /**
         * \brief Increase the given monotonic counter of secure Flash.
         *
         * \param[in]  sf_ctx           The specific secure Flash context
         * \param[in]  mc_addr          Target monotonic counter address
         * \param[out] mc               Pointer to buffer storing current
         *                              counter value
         *
         * \return SECUREFLASH_ERROR_OK if successful,
         *         or a specific SECUREFLASH_ERROR_XXX error code
         */
        int32_t (*increase_mc)(sf_ctx_t *sf_ctx, uint8_t mc_addr, uint8_t *mc);
        /**
         * \brief Read data from secure Flash without security operations.
         *
         * \param[in]  sf_ctx           The specific secure Flash context
         * \param[out] buffer           Pointer to buffer storing data read from
         *                              secure Flash
         * \param[in]  addr             Target address
         * \param[in]  size             Number of data items to read in bytes
         *
         * \return SECUREFLASH_ERROR_OK if successful,
         *         or a specific SECUREFLASH_ERROR_XXX error code
         */
        int32_t (*read)(sf_ctx_t *sf_ctx, uint8_t *buffer,
                        size_t addr, size_t size);
        /**
         * \brief Program data to secure Flash without security operations.
         *
         * \param[in] sf_ctx            The specific secure Flash context
         * \param[in] buffer            Pointer to buffer containing data to be
         *                              programmed to secure Flash
         * \param[in] addr              Target address
         * \param[in] size              Number of data items to program in bytes
         *
         * \return SECUREFLASH_ERROR_OK if successful,
         *         or a specific SECUREFLASH_ERROR_XXX error code
         */
        int32_t (*program)(sf_ctx_t *sf_ctx, const uint8_t *buffer,
                           size_t addr, size_t size);
        /**
         * \brief Erase secure Flash without security operations.
         *
         * \param[in] sf_ctx            The specific secure Flash context
         * \param[in] addr              Address of sector/block to be erased
         * \param[in] size              Size to be erased in bytes
         *
         * \return SECUREFLASH_ERROR_OK if successful,
         *         or a specific SECUREFLASH_ERROR_XXX error code
         */
        int32_t (*erase)(sf_ctx_t *sf_ctx, size_t addr, size_t size);
        /**
         * \brief Send read secure Flash SFDP command.
         *
         * \param[in]  inst            Read SFDP instruction
         * \param[out] rx_buffer       Buffer containing data read from
         *                             secure Flash
         * \param[in]  rx_length       The size of buffer in bytes
         * \param[in]  addr            Target address
         * \param[in]  addr_length     The size of address in bytes
         * \param[in]  dummy_cycles    The size of dummy data in bytes
         * \return SECUREFLASH_ERROR_OK if successful,
         *         or a specific SECUREFLASH_ERROR_XXX error code
         */
        int32_t (*send_read_sfdp_command)(uint8_t inst, uint8_t *rx_buffer,
                                          size_t rx_length,
                                          size_t addr, uint8_t addr_length,
                                          uint8_t dummy_cycles);
        /**
         * \brief Get underlying secure Flash's application
         *        provisioning information.
         *
         * \param[in]  sf_ctx          The specific secure Flash context
         * \param[out] app_info        Pointer to application provisioning
         *                             information
         *
         * \return SECUREFLASH_ERROR_OK if successful,
         *         or a specific SECUREFLASH_ERROR_XXX error code
         */
        int32_t (*get_app_info)(sf_ctx_t *sf_ctx, void *app_info);
        /**
          * \brief Check whether a cipher algorithm is supported by secure Flash.
          *
          * \param[in]  sf_ctx        The specific secure Flash context
          * \param[out] alg           Cipher algorithm
          *
          * \return SECUREFLASH_ERROR_OK if successful,
          *         or a specific SECUREFLASH_ERROR_XXX error code
          */
        int32_t (*check_algorithm_support)(sf_ctx_t *sf_ctx, int32_t alg);
    } vendor_op;
    flash_profile_t flash_profile;
    session_info_t session_info[SESSION_INFO_MAX_NUM];
    struct sfdp_hdr_info sfdp_info;
    void *priv_vendor;
};
/* \} addtogroup secureflash_common */
#endif  /* _SECUREFLASH_COMMON_DEFS_H */
