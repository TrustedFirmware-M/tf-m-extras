/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef _SECUREFLASH_COMMON_H
#define _SECUREFLASH_COMMON_H

#include "secureflash_defs.h"

#define SECURE_FLASH_CONTEXT_NUM 4     /* secure flash common context numbers */
#define SECURE_FLASH_MAX_PUF_SIZE 128  /* PUF value size in byte */
#define SECURE_FLASH_MAX_TRNG_SIZE 128 /* The size of random number generated
                                          by TRNG in byte */
#define SECURE_FLASH_MAX_MC_SIZE   32  /* The size of monotonic counter in byte */


/**
 * \brief Evaluates to the minimum of the two parameters.
 */
#define UTILS_MIN(x, y)    (((x) < (y)) ? (x) : (y))

/**
 * \struct vendor_op_register_t
 *
 * \brief Structure holding vendor layer's specific implementation.
 */
typedef struct{
    const void *sf_name;                /*!< The name of underlying secure Flash */
    void (*vendor_op_register)(void *); /*!< The pointer of vendor's specific
                                             implementation register function */
}vendor_op_register_t;


/* SFDP read callback function */
typedef int32_t (*sfdp_reader_func)(sf_ctx_t *, uint64_t, size_t, uint8_t,
                                    uint8_t, void *, uint64_t);

/** \defgroup secureflash_common secure Flash common layer
 * @{
 */
/**
 * \brief Create and return a secure Flash context based on vendor's
 *        specific implementation.
 *
 * \param[in] vendor_impl_cfg    Pointer to the underlying vendor's
 *                               specific implementation
 * \param[out] *sf_ctx           Pointer to the new created secure Flash context
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t sf_common_create_and_init_context(vendor_op_register_t *vendor_impl_cfg,
                                          sf_ctx_t **sf_ctx);
/**
 * \brief Delete a secure Flash context from sf_context_slots
 *        according to the input name.
 *
 * \param[in] name               The name of underlying vendor's secure Flash
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t sf_common_delete_context(const char *name);
/**
 * \brief Initialize a secure Flash context.
 *
 * \param[in] sf_ctx             The specific secure Flash context
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t sf_common_init(sf_ctx_t *sf_ctx);
/**
 * \brief Deinitialize a secure Flash context.
 *
 * \param[in] sf_ctx             The specific secure Flash context
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t sf_common_deinit(sf_ctx_t *sf_ctx);
/**
 * \brief Parse and store provision data.
 *
 * \param[in] sf_ctx             The specific secure Flash context
 * \param[in] provision_data     Pointer to the provision data
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t sf_common_write_provision(sf_ctx_t *sf_ctx, void *provision_data);
/**
 * \brief Read provision data.
 *
 * \param[in] sf_ctx             The specific secure Flash context
 * \param[out] provision_data    Pointer to the provision data
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t sf_common_read_provision(sf_ctx_t *sf_ctx, void *provision_data);
/**
 * \brief  Secure Flash lock down information provisioning.
 *
 * \param[in] sf_ctx             The specific secure Flash context
 * \param[in] provision_data     Pointer to the provisioning data indicating
 *                               lock down information
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t sf_common_lock_provision(sf_ctx_t *sf_ctx, void *provision_data);
/**
 * \brief Create a new session based on key_id.
 *
 * \param[in] sf_ctx             The specific secure Flash context
 * \param[in] key_id             Input key id used to derive session key
 * \param[out] session_id        Generated session id
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t sf_common_create_session(sf_ctx_t *sf_ctx, uint32_t key_id,
                                 uint32_t *session_id);
/**
 * \brief Close a session specified by session_id.
 *
 * \param[in] sf_ctx             The specific secure Flash context
 * \param[in] session_id         The id of a session to be closed
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t sf_common_close_session(sf_ctx_t *sf_ctx, uint32_t session_id);
/**
 * \brief Read data from secure Flash with a secure session
 *        specified by session_id.
 *
 * \param[in] sf_ctx             The specific secure Flash context
 * \param[out] buffer            Pointer to a buffer storing the data read
 *                               from secure Flash
 * \param[in] addr               Target address
 * \param[in] size               Number of data items to read in bytes
 * \param[in] session_id         The session id
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t sf_common_secure_read(sf_ctx_t *sf_ctx, uint8_t *buffer, size_t addr,
                              size_t size, uint32_t session_id);
/**
 * \brief Program data to secure Flash with a secure session specified
 *        by session_id.
 *
 * \param[in] sf_ctx             The specific secure Flash context
 * \param[in] buffer             Pointer to a buffer containing the data to
 *                               be programmed to secure Flash
 * \param[in] addr               Data address
 * \param[in] size               Number of data items to program in bytes
 * \param[in] session_id         The session id
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t sf_common_secure_program(sf_ctx_t *sf_ctx, const uint8_t *buffer,
                                 size_t addr, size_t size, uint32_t session_id);
/**
 * \brief Erase secure Flash with a secure session specified by session_id.
 *
 * \param[in] sf_ctx             The specific secure Flash context
 * \param[in] addr               Address of sector/block to be erased
 * \param[in] size               Erase size in bytes
 * \param[in] session_id         The session id
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t sf_common_secure_erase(sf_ctx_t *sf_ctx, size_t addr, size_t size,
                               uint32_t session_id);
/*int32_t sf_common_rpmc_write_root_key(sf_ctx_t *sf_ctx, uint8_t mc_addr,
                                        uint8_t *root_key);*/
/**
 * \brief Update the HMAC key of a monotonic counter.
 *
 * \param[in] sf_ctx             The specific secure Flash context
 * \param[in] mc_addr            Address of target monotonic counter
 * \param[in] root_key_id        The root key id
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t sf_common_rpmc_update_hmac_key(sf_ctx_t *sf_ctx, uint8_t mc_addr,
                                       uint32_t root_key_id);
/**
 * \brief Get an unique value based on secure Flash Physical
 *        Unclonable Function.
 *
 * \param[in]  sf_ctx            The specific secure Flash context
 * \param[out] puf               Pointer to a buffer storing value to be derived
 * \param[in]  size              Size of the buffer
 * \param[out] actual_size       The actual size of derived value in bytes
 * \param[in]  input_param       Buffer containing input parameters
 * \param[in]  input_param_size  The size of input_data in bytes
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t sf_common_get_puf(sf_ctx_t *sf_ctx, uint8_t *puf, uint8_t size,
                          uint8_t *actual_size, uint8_t *input_param,
                          uint8_t input_param_size);
/**
 * \brief Get the unique id of secure Flash.
 *
 * \param[in]  sf_ctx            The specific secure Flash context
 * \param[out] uid               Pointer to a buffer storing derived unique id
 * \param[in]  size              Size of the buffer
 * \param[out] actual_size       The actual size of derived unique id in bytes
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t sf_common_get_uid(sf_ctx_t *sf_ctx, uint8_t *uid, uint8_t size,
                          uint8_t *actual_size);
/**
 * \brief Get a true random number from secure Flash True Random
 *        Number Generator.
 *
 * \param[in]  sf_ctx            The specific secure Flash context
 * \param[out] random            Pointer to buffer storing derived random number
 * \param[in]  size              Size of the buffer
 * \param[out] actual_size       The actual size of derived random number
 *                               in bytes
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t sf_common_get_trng(sf_ctx_t *sf_ctx, uint8_t *random, uint8_t size,
                           uint8_t *actual_size);
/**
 * \brief Read the given monotonic counter of secure Flash.
 *
 * \param[in]  sf_ctx            The specific secure Flash context
 * \param[in]  mc_addr           Target monotonic counter
 * \param[out] mc                Pointer to a buffer storing counter value
 * \param[in]  size              Size of buffer in bytes
 * \param[out] actual_size       The actual size of counter value in bytes
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t sf_common_get_mc(sf_ctx_t *sf_ctx, uint8_t mc_addr, uint8_t *mc,
                         uint8_t size, uint8_t *actual_size);
/**
 * \brief Increase the given monotonic counter of secure Flash.
 *
 * \param[in]  sf_ctx            The specific secure Flash context
 * \param[in]  mc_addr           Target monotonic counter
 * \param[out] mc                Pointer to buffer storing current counter value
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t sf_common_increase_mc(sf_ctx_t *sf_ctx, uint8_t mc_addr, uint8_t *mc);
/**
 * \brief Read data from secure Flash without security operations.
 *
 * \param[in]  sf_ctx            The specific secure Flash context
 * \param[out] buffer            Pointer to a buffer storing data read from
 *                               secure Flash
 * \param[in]  addr              Data address
 * \param[in]  size              Number of data items to read in bytes
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t sf_common_read(sf_ctx_t *sf_ctx, uint8_t *buffer,
                       size_t addr, size_t size);
/**
 * \brief Program data to secure Flash without security operations.
 *
 * \param[in] sf_ctx             The specific secure Flash context
 * \param[in] buffer             Pointer to a buffer containing data to be
 *                               programmed to secure Flash
 * \param[in] addr               Data address
 * \param[in] size               Number of data items to program in bytes
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t sf_common_program(sf_ctx_t *sf_ctx, uint8_t *buffer,
                          size_t addr, size_t size);
/**
 * \brief Erase secure Flash without security operations.
 *
 * \param[in] sf_ctx             The specific secure Flash context
 * \param[in] addr               Address of sector/block to be erased
 * \param[in] size               Size to be erased in bytes
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t sf_common_erase(sf_ctx_t *sf_ctx, size_t addr, size_t size);
/**
 * \brief Get underlying secure Flash's application provisioning information.
 *
 * \param[in]  sf_ctx           The specific secure Flash context
 * \param[out] app_info         Pointer to application provisioning information
 *
 * \return SECUREFLASH_ERROR_OK if successful,
 *         or a specific SECUREFLASH_ERROR_XXX error code
 */
int32_t sf_common_get_app_info(sf_ctx_t *sf_ctx, void *app_info);
/**
 * \brief Get underlying secure Flash's security read size.
 *
 * \param[in] sf_ctx            The specific secure Flash context
 *
 * \return The security read size in bytes
 */
uint64_t sf_common_get_secure_read_size(sf_ctx_t *sf_ctx);
/**
 * \brief Get underlying secure Flash's security program size.
 *
 * \param[in] sf_ctx            The specific secure Flash context
 *
 * \return The security program size in bytes
 */
uint64_t sf_common_get_secure_program_size(sf_ctx_t *sf_ctx);
/**
 * \brief Get underlying secure Flash's security erase size.
 *
 * \param[in] sf_ctx            The specific secure Flash context
 *
 * \return The security erase size in bytes
 */
uint64_t sf_common_get_secure_erase_size(sf_ctx_t *sf_ctx);
/**
 * \brief Get underlying secure Flash's whole chip size.
 *
 * \param[in] sf_ctx            The specific secure Flash context
 *
 * \return The whole chip size in bytes
 */
uint64_t sf_common_get_chip_size(sf_ctx_t *sf_ctx);
/**
 * \brief Get underlying secure Flash's individual data zone size.
 *
 * \param[in] sf_ctx            The specific secure Flash context
 *
 * \return The data zone size in bytes
 */
uint64_t sf_common_get_zone_size(sf_ctx_t *sf_ctx);
/**
 * \brief Get underlying secure Flash's data zone number.
 *
 * \param[in] sf_ctx            The specific secure Flash context
 *
 * \return The data zone number
 */
uint64_t sf_common_get_zone_number(sf_ctx_t *sf_ctx);
/**
 * \brief Get underlying secure Flash's whole security region size.
 *
 * \param[in] sf_ctx            The specific secure Flash context
 *
 * \return The whole security region size in bytes
 */
uint64_t sf_common_get_zone_total_size(sf_ctx_t *sf_ctx);
/**@}*/

#endif  /* _SECUREFLASH_COMMON_H */
