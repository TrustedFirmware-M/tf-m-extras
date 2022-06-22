/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __MEASURED_BOOT_UTILS_H__
#define __MEASURED_BOOT_UTILS_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Logs all the measurement parameters used to extend the requested slot.
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
 */
void log_extend_measurement(uint8_t index,
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

#ifdef __cplusplus
}
#endif

#endif /* __MEASURED_BOOT_UTILS_H__ */
