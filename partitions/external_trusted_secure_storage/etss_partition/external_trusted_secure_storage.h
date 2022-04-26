/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __EXTERNAL_TRUSTED_SECURE_STORAGE_H__
#define __EXTERNAL_TRUSTED_SECURE_STORAGE_H__

#include <stddef.h>
#include <stdint.h>

#include "psa/error.h"
#include "psa/storage_common.h"
#include "etss/etss_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Initializes the external trusted secure storage system.
 *
 * \return A status indicating success/failure of the operation as specified
 *         in \ref etss_err_t
 *
 * \retval ETSS_SUCCESS                  The operation completed successfully
 * \retval ETSS_ERR_STORAGE_FAILURE      The operation failed because the
 *                                       storage system initialization has
 *                                       failed (fatal error)
 * \retval ETSS_ERR_GENERIC_ERROR        The operation failed because of an
 *                                       unspecified internal failure
 */
etss_err_t etss_init(void);

/**
 * \brief Secure Flash provisioning
 *
 * \param[in] client_id                  Identifier of client
 * \param[in] prov_data                  Pointer to the provisioning data
 * \param[in] data_length                The length of provisioning data
 *
 * \return  ETSS_SUCCESS if operation succeed. Otherwise,
 *          it returns ETSS_XXX_ERROR.
 */
etss_err_t etss_secure_flash_provisioning(int32_t client_id, uint8_t *prov_data,
                                          size_t data_length);

/**
 * \brief Create a new, or modify an existing, uid/value pair
 *
 * Stores data in the external trusted secure storage.
 *
 * \param[in] client_id                  Identifier of the asset's owner (client)
 * \param[in] uid                        The identifier for the data
 * \param[in] data_length                The size in bytes of data in `p_data`
 * \param[in] create_flags               The flags that data will be stored with
 *
 * \return A status indicating the success/failure of the operation
 *
 * \retval ETSS_SUCCESS                  The operation completed successfully
 * \retval ETSS_ERR_NOT_PERMITTED        The operation failed because the
 *                                       provided `uid` value was already
 *                                       created with SA_STORAGE_FLAG_WRITE_ONCE
 * \retval ETSS_ERR_NOT_SUPPORTED        The operation failed because one or
 *                                       more of the flags provided in
 *                                       create_flags` is not supported or is
 *                                       not valid
 * \retval ETSS_ERR_INSUFFICIENT_STORAGE The operation failed because there
 *                                       was insufficient space on the
 *                                       storage medium
 * \retval ETSS_ERR_STORAGE_FAILURE      The operation failed because the
 *                                       physical storage has failed (Fatal
 *                                       error)
 * \retval ETSS_ERR_INVALID_ARGUMENT     The operation failed because one
 *                                       of the provided pointers (`p_data`)
 *                                       is invalid, for example is `NULL` or
 *                                       references memory the caller cannot
 *                                       access
 */
etss_err_t etss_set(int32_t client_id,
                    psa_storage_uid_t uid,
                    size_t data_length,
                    psa_storage_create_flags_t create_flags);

/**
 * \brief Retrieve data associated with a provided UID
 *
 * Retrieves up to `data_size` bytes of the data associated with `uid`, starting
 * at `data_offset` bytes from the beginning of the data. Upon successful
 * completion, the data will be placed in the `p_data` buffer, which must be at
 * least `data_size` bytes in size. The length of the data returned will be in
 * `p_data_length`. If `data_size` is 0, the contents of `p_data_length` will
 * be set to zero.
 *
 * \param[in]  client_id                Identifier of the asset's owner (client)
 * \param[in]  uid                      The uid value
 * \param[in]  data_offset              The starting offset of the data
 *                                      requested
 * \param[in]  data_size                The amount of data requested
 * \param[out] p_data_length            On success, this will contain size of
 *                                      the data placed in `p_data`.
 *
 * \return A status indicating the success/failure of the operation
 *
 * \retval ETSS_SUCCESS                 The operation completed successfully
 * \retval ETSS_ERR_DOES_NOT_EXIST      The operation failed because the
 *                                      provided `0uid` value was not found in
 *                                      the storage
 * \retval ETSS_ERR_STORAGE_FAILURE     The operation failed because the
 *                                      physical storage has failed (Fatal error)
 * \retval ETSS_ERR_INVALID_ARGUMENT    The operation failed because one of the
 *                                      provided arguments (`p_data`,
 *                                      `p_data_length`) is invalid, such as
 *                                      is `NULL` or references memory the
 *                                      caller cannot access. In addition, this
 *                                      can also happen if `data_offset` is
 *                                      larger than the size of the data
 *                                      associated with `uid`.
 */
etss_err_t etss_get(int32_t client_id,
                    psa_storage_uid_t uid,
                    size_t data_offset,
                    size_t data_size,
                    size_t *p_data_length);

/**
 * \brief Retrieve the metadata about the provided uid
 *
 * Retrieves the metadata stored for a given `uid` as a `psa_storage_info_t`
 * structure.
 *
 * \param[in]  client_id  Identifier of the asset's owner (client)
 * \param[in]  uid        The `uid` value
 * \param[out] p_info     A pointer to the `psa_storage_info_t` struct that will
 *                        be populated with the metadata
 *
 * \return A status indicating the success/failure of the operation
 *
 * \retval ETSS_SUCCESS                  The operation completed successfully
 * \retval ETSS_ERR_DOES_NOT_EXIST       The operation failed because the
 *                                       provided uid value was not found in
 *                                       the storage
 * \retval ETSS_ERR_STORAGE_FAILURE      The operation failed because the
 *                                       physical storage has failed (Fatal
 *                                       error)
 * \retval ETSS_ERR_INVALID_ARGUMENT     The operation failed because one of the
 *                                       provided pointers(`p_info`) is invalid,
 *                                       for example is `NULL` or references
 *                                       memory the caller cannot access
 */
etss_err_t etss_get_info(int32_t client_id, psa_storage_uid_t uid,
                         struct psa_storage_info_t *p_info);

/**
 * \brief Remove the provided uid and its associated data from the storage
 *
 * Deletes the data from external trusted secure storage.
 *
 * \param[in] client_id  Identifier of the asset's owner (client)
 * \param[in] uid        The `uid` value
 *
 * \return A status indicating the success/failure of the operation
 *
 * \retval ETSS_SUCCESS                   The operation completed successfully
 * \retval ETSS_ERR_INVALID_ARGUMENT      The operation failed because one or
 *                                        more of the given arguments were
 *                                        invalid (null pointer, wrong flags
 *                                        and so on)
 * \retval ETSS_ERR_DOES_NOT_EXIST        The operation failed because the
 *                                        provided uid value was not found in
 *                                        the storage
 * \retval ETSS_ERR_NOT_PERMITTED         The operation failed because the
 *                                        provided uid value was created with
 *                                        PSA_STORAGE_FLAG_WRITE_ONCE
 * \retval ETSS_ERR_STORAGE_FAILURE       The operation failed because the
 *                                        physical storage has failed (Fatal
 *                                        error)
 */
etss_err_t etss_remove(int32_t client_id, psa_storage_uid_t uid);
/**
 * \brief Get PUF generated secret values of secure Flash
 *
 * Get the unclonable secret values generated from secure Flash's PUF.
 *
 * \param[in]  client_id   Identifier of client
 * \param[in]  buf_size    Buffer size
 * \param[out] puf_len     Pointer to store the actual size of unique value
 * \return A status indicating the success/failure of the operation
 *
 * \retval ETSS_SUCCESS                   The operation completed successfully
 * \retval ETSS_ERR_INVALID_ARGUMENT      The operation failed because one or
 *                                        more of the given arguments were
 *                                        invalid (null pointer and so on)
 * \retval ETSS_ERR_NOT_SUPPORTED         The operation failed because the
 *                                        external secure storage does not
 *                                        support PUF
 * \retval ETSS_ERR_STORAGE_FAILURE       The operation failed because the
 *                                        physical storage has failed (Fatal
 *                                        error)
 */
etss_err_t etss_get_puf(int32_t client_id, size_t buf_size, size_t *puf_len);
/**
 * \brief Retrieve random number generated by external trusted secure storage
 *        TRNG
 *
 * Get random number generated by TRNG from external trusted secure storage.
 *
 * \param[in]  client_id    Identifier of client
 * \param[in]  buf_size     Size of buffer
 * \param[out] random_len   Pointer to store the actual size of random number
 * \return A status indicating the success/failure of the operation
 *
 * \retval ETSS_SUCCESS                   The operation completed successfully
 * \retval ETSS_ERR_INVALID_ARGUMENT      The operation failed because one or
 *                                        more of the given arguments were
 *                                        invalid (null pointer, and so on)
 * \retval ETSS_ERR_NOT_SUPPORTED         The operation failed because the
 *                                        external secure storage does not
 *                                        support TRNG
 * \retval ETSS_ERR_STORAGE_FAILURE       The operation failed because the
 *                                        physical storage has failed (Fatal
 *                                        error)
 */
etss_err_t etss_generate_random_number(int32_t client_id, size_t buf_size,
                                       size_t *random_len);

/**
 * \brief Increments the given monotonic counter's value by one
 * \param[in] client_id    Identifier of client
 * \param[in] mc_id        Target counter
 *
 * \return  ETSS_SUCCESS if the counter is increased by one successfully.
 *          Otherwise, it returns ETSS_XXX_ERROR.
 */
etss_err_t etss_mc_increment(int32_t client_id, uint8_t mc_id);
/**
 * \brief Reads current value of the given monotonic counter
 *
 * \param[in] client_id    Identifier of client
 * \param[in] mc_id        Target counter
 * \param[in] size         Size of the buffer to store counter value
 *                         in bytes.
 *
 * \return  ETSS_SUCCESS if operation succeed. Otherwise,
 *          it returns ETSS_XXX_ERROR.
 */
etss_err_t etss_mc_get(int32_t client_id, uint8_t mc_id, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* __EXTERNAL_TRUSTED_SECURE_STORAGE_H__ */
