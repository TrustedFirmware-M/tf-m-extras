/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef __MEASURED_BOOT_COMMON_H__
#define __MEASURED_BOOT_COMMON_H__

#include "measured_boot_api.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct measurement_metadata_t {
    uint8_t  signer_id[SIGNER_ID_MAX_SIZE];
    size_t   signer_id_size;
    uint8_t  version[VERSION_MAX_SIZE];
    size_t   version_size;
    uint32_t measurement_algo;
    uint8_t  sw_type[SW_TYPE_MAX_SIZE];
    size_t   sw_type_size;
};

struct measurement_value_t {
    uint8_t hash_buf[MEASUREMENT_VALUE_MAX_SIZE];
    uint8_t hash_buf_size;
};

struct measurement_t {
    struct measurement_value_t value;                   /* measurement value */
    struct measurement_metadata_t metadata;             /* metadata */
};

struct test_buf_t {
    const void *ptr;
    size_t      len;
} ;

struct test_measurement_data_t  {
    uint8_t slot_index;
    uint32_t measurement_algo;
    struct test_buf_t signer_id;
    struct test_buf_t version;
    struct test_buf_t sw_type;
    struct test_buf_t hash_buf;
};

/**
 * \brief Load default valid test measurement data.
 *
 * \param[out]  measurement    Pointer to \p measurement where test data is to
 *                             be loaded.
 */
void load_default_valid_test_data(struct measurement_t *measurement);

/**
 * \brief Load test measurement value.
 *
 * \param[in]  test_data_ptr   Pointer to \p test_data_ptr.
 * \param[out  measurement     Pointer to \p measurement.
 * \param[out] slot_index      Pointer to \p slot_index.
 */
void load_test_measurement_data(struct test_measurement_data_t *test_data_ptr,
                                struct measurement_t *measurement,
                                uint8_t *slot_index);

/**
 * \brief Load test measurement hash values to input buffer.
 *
 * \param[in] slot_index       Slot number in which measurement is to be stored.
 * \param[in] measurement      Pointer to \p measurement buffer.
 * \param[in] lock_measurement Boolean flag requesting whether the measurement
 *                             is to be locked.
 * \return Returns values as specified by the \ref psa_status_t
 */
psa_status_t extend_measurement(uint8_t slot_index,
                                struct measurement_t *measurement,
                                bool lock_measurement);

/**
 * \brief Initialises the measurement to default values.
 *
 * \param[in] measurement      Pointer to \p measurement.
 */
void initialise_measurement(struct measurement_t *measurement);

/**
 * \brief Read measurement for a given slot.
 *
 * \param[in] slot_index       Slot number from which measurement is to be read.
 * \param[in] measurement      Pointer to \p measurement.
 * \param[in] is_locked        Pointer to \p is_locked.
 *
 * \return Returns values as specified by the \ref psa_status_t
 */
psa_status_t read_measurement(uint8_t slot_index,
                              struct measurement_t *measurement,
                              bool *is_locked);

#ifdef __cplusplus
}
#endif

#endif /* __MEASURED_BOOT_COMMON_H__ */
