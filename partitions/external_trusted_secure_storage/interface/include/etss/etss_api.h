/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

/**
 * \file etss_api.h
 *
 * \brief This file describes the External Trusted Secure Storage API
 *
 */
#ifndef _ETSS_API_H_
#define _ETSS_API_H_

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

#include "etss_defs.h"
#include "tfm_api.h"
#include "psa/storage_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** \defgroup version API version
 * @{
 */

/**
 * \brief etss partition API version
 */
#define ETSS_API_VERSION_MAJOR (0)
#define ETSS_API_VERSION_MINOR (1)

/**@}*/

/**
 * \brief Secure Flash provisioning
 *
 *
 * \param[in] data_length           The size in bytes of the data in `p_data`
 * \param[in] p_data                A buffer containing provisioning data
 *
 * \return A status indicating the success/failure of the operation
 *

 * \retval ETSS_SUCCESS                The operation completed successfully
 * \retval ETSS_ERR_STORAGE_FAILURE    The operation failed because the
 *                                     physical storage has failed (Fatal error)
 * \retval ETSS_ERR_SF_PROVISION       The operation failed because secure flash
 *                                     write provision has failed
 */
etss_err_t tfm_etss_secure_flash_provisioning(size_t data_length,
                                              const void *p_data);

/**
 * \brief Create a new, or modify an existing, uid/value pair
 *
 * Stores data in the external trusted secure storage.
 *
 * \param[in] uid                   The identifier for the data
 * \param[in] data_length           The size in bytes of the data in `p_data`
 * \param[in] p_data                Pointer to the data
 * \param[in] create_flags          The flags that the data will be stored with
 *
 * \return A status indicating the success/failure of the operation
 *

 * \retval ETSS_SUCCESS                   The operation completed successfully
 * \retval ETSS_ERR_NOT_PERMITTED         The operation failed because the
 *                                        provided `uid` value was already
 *                                        created with
 *                                        PSA_STORAGE_FLAG_WRITE_ONCE
 * \retval ETSS_ERR_NOT_SUPPORTED         The operation failed because one or
 *                                        more of the flags provided in
 *                                        `create_flags` is not supported or is
 *                                        not valid
 * \retval ETSS_ERR_INSUFFICIENT_STORAGE  The operation failed because there
 *                                        was insufficient space on the
 *                                        storage medium
 * \retval ETSS_ERR_STORAGE_FAILURE       The operation failed because the
 *                                        physical storage has failed (Fatal
 *                                        error)
 * \retval ETSS_ERR_INVALID_ARGUMENT      The operation failed because one
 *                                        of the provided pointers(`p_data`)
 *                                        is invalid, for example is `NULL` or
 *                                        references memory the caller cannot
 *                                        access
 */
etss_err_t tfm_etss_set(psa_storage_uid_t uid,
                        size_t data_length,
                        const void *p_data,
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
 * \param[in]  uid                        The uid value
 * \param[in]  data_offset                The starting offset of data requested
 * \param[in]  data_size                  The amount of data requested
 * \param[out] p_data                     On success, the buffer where the data
 *                                        will be placed
 * \param[out] p_data_length              On success, this will contain size
 *                                        of the data placed in `p_data`
 * \return A status indicating the success/failure of the operation
 *
 * \retval ETSS_SUCCESS                    The operation completed successfully
 * \retval ETSS_ERROR_DOES_NOT_EXIST       The operation failed because the
 *                                         provided `uid` value was not found
 *                                         in the storage
 * \retval ETSS_ERROR_STORAGE_FAILURE      The operation failed because the
 *                                         physical storage has failed (Fatal
 *                                         error)
 * \retval ETSS_ERROR_INVALID_ARGUMENT     The operation failed because one of
 *                                         the provided arguments (`p_data`,
 *                                         `p_data_length`) is invalid,
 *                                         for example is `NULL` or references
 *                                         memory the caller cannot access.
 *                                         In addition, this can also happen
 *                                         if `data_offset` is larger than the
 *                                         size of the data associated with
 *                                         `uid`
 */
etss_err_t tfm_etss_get(psa_storage_uid_t uid,
                        size_t data_offset,
                        size_t data_size,
                        void *p_data,
                        size_t *p_data_length);

/**
 * \brief Retrieve the metadata about the provided uid
 *
 * Retrieves the metadata stored for a given `uid` as a `psa_storage_info_t`
 * structure.
 *
 * \param[in]  uid           The `uid` value
 * \param[out] p_info        A pointer to the `psa_storage_info_t` struct that
 *                           will be populated with the metadata
 *
 * \return A status indicating the success/failure of the operation
 *
 * \retval ETSS_SUCCESS                     The operation completed successfully
 * \retval ETSS_ERR_DOES_NOT_EXIST          The operation failed because the
 *                                          provided uid value was not found
 *                                          in the storage
 * \retval ETSS_ERR_STORAGE_FAILURE         The operation failed because the
 *                                          physical storage has failed (Fatal
 *                                          error)
 * \retval ETSS_ERR_INVALID_ARGUMENT        The operation failed because one of
 *                                          the provided pointers(`p_info`)
 *                                          is invalid, for example is `NULL` or
 *                                          references memory the caller cannot
 *                                          access
 */
etss_err_t tfm_etss_get_info(psa_storage_uid_t uid,
                             struct psa_storage_info_t *p_info);
/**
 * \brief Remove the provided uid and its associated data from the storage
 *
 * Deletes the data from external trusted secure storage.
 *
 * \param[in] uid        The `uid` value
 *
 * \return A status indicating the success/failure of the operation
 *
 * \retval ETSS_SUCCESS                     The operation completed successfully
 * \retval ETSS_ERR_INVALID_ARGUMENT        The operation failed because one or
 *                                          more of the given arguments were
 *                                          invalid (null pointer and so on)
 * \retval ETSS_ERR_DOES_NOT_EXIST          The operation failed because the
 *                                          provided uid value was not found
 *                                          in the storage
 * \retval ETSS_ERR_NOT_PERMITTED           The operation failed because the
 *                                          provided uid value was created with
 *                                          PSA_STORAGE_FLAG_WRITE_ONCE
 * \retval ETSS_ERR_STORAGE_FAILURE         The operation failed because the
 *                                          physical storage has failed (Fatal
 *                                          error)
 */
etss_err_t tfm_etss_remove(psa_storage_uid_t uid);

/**
 * \brief Get PUF generated secret values of secure Flash
 *
 * Get the unclonable secret values generated from secure Flash's PUF
 *
 * \param[out] buf             Buffer to store the PUF code
 * \param[in]  buf_size        Size of buffer to store the PUF code
 * \param[out] puf_len         Pointer to store the actual size of PUF code
 * \return A status indicating the success/failure of the operation
 *
 * \retval ETSS_SUCCESS                     The operation completed successfully
 * \retval ETSS_ERR_INVALID_ARGUMENT        The operation failed because one or
 *                                          more of the given arguments were
 *                                          invalid (null pointer and so on)
 * \retval ETSS_ERR_NOT_SUPPORTED           The operation failed because the
 *                                          external secure storage does not
 *                                          support PUF
 * \retval ETSS_ERR_STORAGE_FAILURE         The operation failed because the
 *                                          physical storage has failed (Fatal
 *                                          error)
 */
etss_err_t tfm_etss_get_puf(uint8_t *buf, uint32_t buf_size, uint32_t *puf_len);

/**
 * \brief Retrieve random number generated by external secure Flash's TRNG(True
 *        Random Number Generator)
 * Get random number generated by True Random Number Generator of secure Flash.
 *
 * \param[out] buf        Buffer to store the random number
 * \param[in]  buf_size   Size of buffer
 * \param[out] random_len Pointer to store the actual size of random number
 * \return A status indicating the success/failure of the operation
 *
 * \retval ETSS_SUCCESS                     The operation completed successfully
 * \retval ETSS_ERR_INVALID_ARGUMENT        The operation failed because one or
 *                                          more of the given arguments were
 *                                          invalid (null pointer, and so on)
 * \retval ETSS_ERR_NOT_SUPPORTED           The operation failed because the
 *                                          external secure storage does not
 *                                          support TRNG
 * \retval ETSS_ERR_STORAGE_FAILURE         The operation failed because the
 *                                          physical storage has failed (Fatal
 *                                          error)
 */
etss_err_t tfm_etss_generate_random_number(uint8_t *buf, uint32_t buf_size);

/**
 * \brief Increase external secure Flash's monotonic counter
 *
 *  Increase external secure Flash's monotonic counter specified by mc_id.
 *
 * \param[in]  mc_id   Specify the monotonic counter which should be increased.
 * \return A status indicating the success/failure of the operation
 *
 * \retval ETSS_SUCCESS                     The operation completed successfully
 * \retval ETSS_ERR_INVALID_ARGUMENT        The operation failed because the
 *                                          given arguments were invalid (null
 *                                          pointer, wrong flags and so on)
 * \retval ETSS_ERR_NOT_SUPPORTED           The operation failed because the
 *                                          external secure storage does not
 *                                          support monotonic counter
 * \retval ETSS_ERR_STORAGE_FAILURE         The operation failed because the
 *                                          physical storage has failed (Fatal
 *                                          error)
 */
etss_err_t tfm_etss_mc_increment(uint8_t mc_id);

/**
 * \brief Get the specific monotonic counter value of external secure Flash
 *
 *  Get current value of monotonic counter specified by mc_id of the external
 *  secure Flash.
 *
 * \param[in]  mc_id   Specify the monotonic counter which should be increased.
 * \return A status indicating the success/failure of the operation
 *
 * \retval ETSS_SUCCESS                     The operation completed successfully
 * \retval ETSS_ERR_INVALID_ARGUMENT        The operation failed because one or
 *                                          more of the given arguments were
 *                                          invalid(null pointer, wrong flags
 *                                          and so on)
 * \retval ETSS_ERR_NOT_SUPPORTED           The operation failed because the
 *                                          external secure storage does not
 *                                          support monotonic counter
 * \retval ETSS_ERR_STORAGE_FAILURE         The operation failed because the
 *                                          physical storage has failed (Fatal
 *                                          error)
 */
etss_err_t tfm_etss_mc_get(uint8_t mc_id, uint8_t *buf, uint32_t buf_size);
#endif /* _ETSS_API_H_ */
