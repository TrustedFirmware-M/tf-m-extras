/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __MEASURED_BOOT_H__
#define __MEASURED_BOOT_H__

#include "psa/error.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

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
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The size of at least one of the output buffers is incorrect.
 * \retval #PSA_ERROR_NOT_PERMITTED
 *         When the requested slot is not accessible to the caller.
 * \retval #PSA_ERROR_DOES_NOT_EXIST
 *         The requested slot is empty, does not contain a measurement.
 */
psa_status_t measured_boot_read_measurement(uint8_t index,
                                            uint8_t *signer_id,
                                            size_t signer_id_size,
                                            size_t *signer_id_len,
                                            uint8_t *version,
                                            size_t version_size,
                                            uint8_t *version_len,
                                            uint32_t *measurement_algo,
                                            uint8_t *sw_type,
                                            size_t sw_type_size,
                                            uint8_t *sw_type_len,
                                            uint8_t *measurement_value,
                                            size_t measurement_value_size,
                                            size_t *measurement_value_len,
                                            uint8_t *is_locked);

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
 * \param[in] lock_measurement           Flag requesting whether the
 *                                       measurement is to be locked.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_BAD_STATE
 *         Request to lock, when slot is already locked.
 * \retval #PSA_ERROR_NOT_PERMITTED
 *         When the requested slot is not accessible to the caller.
 */
psa_status_t measured_boot_extend_measurement(uint8_t index,
                                              const uint8_t *signer_id,
                                              size_t signer_id_size,
                                              const uint8_t *version,
                                              uint8_t version_size,
                                              uint32_t measurement_algo,
                                              const uint8_t *sw_type,
                                              uint8_t sw_type_size,
                                              const uint8_t *measurement_value,
                                              size_t measurement_value_size,
                                              uint8_t lock_measurement);

/**
 * \brief Initialise all measurements & related metadata
 *
 */
void initialise_all_measurements(void);

/**
 * \brief Collect and store every measurement from the shared memory.
 *
 * \return Returns values as specified by the \ref psa_status_t
 */
psa_status_t collect_shared_measurements(void);

#ifdef __cplusplus
}
#endif

#endif /* __MEASURED_BOOT_H__ */
