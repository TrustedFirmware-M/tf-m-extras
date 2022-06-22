/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

/* This file describes the TFM Measured Boot API */

#ifndef __MEASURED_BOOT_API__
#define __MEASURED_BOOT_API__

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "psa/error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Minimum measurement value size that can be requested to store */
#define MEASUREMENT_VALUE_MIN_SIZE          32U
/* Maximum measurement value size that can be requested to store */
#define MEASUREMENT_VALUE_MAX_SIZE          64U
/* Minimum signer id size that can be requested to store */
#define SIGNER_ID_MIN_SIZE   MEASUREMENT_VALUE_MIN_SIZE
/* Maximum signer id size that can be requested to store */
#define SIGNER_ID_MAX_SIZE   MEASUREMENT_VALUE_MAX_SIZE
/* The theoretical maximum image version is: "255.255.65535\0" */
#define VERSION_MAX_SIZE                    14U
/* Example sw_type: "TFM_BLX, AP_BL1, etc." */
#define SW_TYPE_MAX_SIZE                    20U

#define NUM_OF_MEASUREMENT_SLOTS            32U

#define MEASUREMENT_VALUE_INIT_PATTERN        0

/**
 * \brief Retrieves a measurement from the requested slot.
 *
 * \param[in]  index                     Slot number from which measurement is
 *                                       to be retrieved.
 * \param[out] signer_id                 Pointer to \p signer_id buffer.
 * \param[in]  signer_id_size            Size of the \p signer_id buffer in
 *                                       bytes.
 * \param[out] signer_id_len             On success, number of bytes that make
 *                                       up \p signer_id.
 * \param[out] version                   Pointer to \p version buffer.
 * \param[in]  version_size              Size of the \p version buffer in bytes.
 * \param[out] version_len               On success, number of bytes that make
 *                                       up the \p version.
 * \param[out] measurement_algo          Pointer to \p measurement_algo.
 * \param[out] sw_type                   Pointer to \p sw_type buffer.
 * \param[in]  sw_type_size              Size of the \p sw_type buffer in bytes.
 * \param[out] sw_type_len               On success, number of bytes that make
 *                                       up the \p sw_type.
 * \param[out] measurement_value         Pointer to \p measurement_value buffer.
 * \param[in]  measurement_value_size    Size of the \p measurement_value
 *                                       buffer in bytes.
 * \param[out] measurement_value_len     On success, number of bytes that make
 *                                       up the \p measurement_value.
 * \param[out] is_locked                 Pointer to lock status of requested
 *                                       measurement slot.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_PROGRAMMER_ERROR
 *         Fails to get caller id.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         When requested slot index is invalid.
 * \retval #PSA_ERROR_NOT_PERMITTED
 *         When Measurement is requested by unauthorised client.
 *         i.e. if client is not the owner of measurement OR
 *         measurement is not accessible to all.
 * \retval #PSA_ERROR_DOES_NOT_EXIST
 *         The requested slot is empty, does not contain a measurement.
 */
psa_status_t tfm_measured_boot_read_measurement(uint8_t index,
                                                uint8_t *signer_id,
                                                size_t signer_id_size,
                                                size_t *signer_id_len,
                                                uint8_t *version,
                                                size_t version_size,
                                                size_t *version_len,
                                                uint32_t *measurement_algo,
                                                uint8_t *sw_type,
                                                size_t sw_type_size,
                                                size_t *sw_type_len,
                                                uint8_t *measurement_value,
                                                size_t measurement_value_size,
                                                size_t *measurement_value_len,
                                                bool *is_locked);

/**
 * \brief Extends and stores a measurement to the requested slot.
 *
 * \param[in] index                      Slot number in which measurement is
 *                                       to be stored.
 * \param[in] signer_id                  Pointer to \p signer_id buffer.
 * \param[in] signer_id_size             Size of the \p signer_id buffer in
 *                                       bytes.
 * \param[in] version                    Pointer to \p version buffer.
 * \param[in] version_size               Size of the \p version buffer in bytes.
 * \param[in] measurement_algo           Algorithm identifier used for
 *                                       measurement.
 * \param[in] sw_type                    Pointer to \p sw_type buffer.
 * \param[in] sw_type_size               Size of the \p sw_type buffer in bytes.
 * \param[in] measurement_value          Pointer to \p measurement_value buffer.
 * \param[in] measurement_value_size     Size of the \p measurement_value
 *                                       buffer in bytes.
 * \param[in] lock_measurement           Boolean flag requesting whether the
 *                                       measurement is to be locked.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The size of any argument is invalid OR
 *         Input Measurement value is NULL OR
 *         Input Signer ID is NULL OR
 *         Requested slot index is invalid.
 * \retval #PSA_ERROR_BAD_STATE
 *         Request to lock, when slot is already locked.
 * \retval #PSA_ERROR_NOT_PERMITTED
 *         When the requested slot is not accessible to the caller.
 *
 * \note   \p measurement_algo value must be a valid PSA hash algorithm
 *         identifier.
*/
psa_status_t tfm_measured_boot_extend_measurement(
                                              uint8_t index,
                                              const uint8_t *signer_id,
                                              size_t signer_id_size,
                                              const uint8_t *version,
                                              size_t version_size,
                                              uint32_t measurement_algo,
                                              const uint8_t *sw_type,
                                              size_t sw_type_size,
                                              const uint8_t *measurement_value,
                                              size_t measurement_value_size,
                                              bool lock_measurement);

#ifdef __cplusplus
}
#endif

#endif /* __MEASURED_BOOT_API__ */
