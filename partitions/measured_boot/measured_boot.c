/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "measured_boot.h"
#include "measured_boot_utils.h"
#include "measured_boot_api.h"
#include "psa/crypto.h"
#include "tfm_api.h"
#include "tfm_boot_status.h"
#include "boot_hal.h"
#include "service_api.h"
#include "tfm_strnlen.h"
#include "tfm_sp_log.h"
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#define TEMP_BUFFER_SIZE (MEASUREMENT_VALUE_SIZE + MEASUREMENT_VALUE_MAX_SIZE)

#ifdef CONFIG_TFM_BOOT_STORE_MEASUREMENTS
/* Size of 1 complete measurement (value + metadata) in TLV format. */
#define SHARED_BOOT_MEASUREMENT_SIZE                                           \
                            ((2 * SHARED_DATA_ENTRY_HEADER_SIZE)               \
                             + sizeof(struct boot_measurement_metadata)        \
                             + MEASUREMENT_VALUE_MAX_SIZE)

/* 2 measurements from the BL1 stages and 1 measurement per image from BL2. */
#define MAX_SHARED_BOOT_DATA_LENGTH     ((2 + MCUBOOT_IMAGE_NUMBER)            \
                                         * SHARED_BOOT_MEASUREMENT_SIZE)

/*!
 * \struct boot_measurement_data
 *
 * \brief Contains all the measurement and related metadata (from BL1 and BL2).
 *
 * \details This is a redefinition of \ref tfm_boot_data to allocate the
 *          appropriate, service dependent size of \ref boot_data.
 */
struct boot_measurement_data {
    struct shared_data_tlv_header header;
    uint8_t data[MAX_SHARED_BOOT_DATA_LENGTH];
};

/*!
 * \var boot_measurements
 *
 * \brief Store the boot measurements in the service's memory.
 *
 * \details Boot measurements come from the BL1 and BL2 boot stages and stored
 *          on a memory area which is shared between the bootloaders and SPM.
 *          SPM provides the \ref tfm_core_get_boot_data() API to retrieve
 *          the service related data from shared area.
 */
__attribute__ ((aligned(4)))
static struct boot_measurement_data boot_measurements;
#endif /* CONFIG_TFM_BOOT_STORE_MEASUREMENTS */

struct measurement_metadata_t {
    uint8_t  signer_id[SIGNER_ID_MAX_SIZE];
    size_t   signer_id_size;
    uint8_t  version[VERSION_MAX_SIZE];
    uint8_t  version_size;
    uint32_t measurement_algo;
    uint8_t  sw_type[SW_TYPE_MAX_SIZE];
    uint8_t  sw_type_size;
};

struct measurement_value_t {
    uint8_t hash_buf[MEASUREMENT_VALUE_MAX_SIZE];
    uint8_t hash_buf_size;
};

struct measurement_t {
    struct measurement_value_t value;       /* measurement value */
    struct measurement_metadata_t metadata; /* metadata */
};

struct measured_boot_slot_t {
    bool is_locked;
    bool is_populated;
    bool is_common;
    struct measurement_t measurement;
};

static struct measured_boot_slot_t measurement_slot[NUM_OF_MEASUREMENT_SLOTS];

static bool is_signer_id_different(uint8_t index, const uint8_t *signer_id)
{
    uint8_t *stored_signer_id =
                     &measurement_slot[index].measurement.metadata.signer_id[0];
    uint8_t stored_signer_id_size =
                    measurement_slot[index].measurement.metadata.signer_id_size;

    if (memcmp(signer_id, stored_signer_id, stored_signer_id_size) != 0) {
        return true;
    }
    return false;
}

/* TODO: Access control strategy to be updated */
static bool is_slot_access_prohibited(uint8_t slot_index,
                                      const uint8_t *signer_id)
{
    if (is_signer_id_different(slot_index, signer_id)) {
        /* The client signer id is different from the current slot signer id */
        if (measurement_slot[slot_index].is_common) {
            /* This slot holds common measurement and must be accessible to
             * all
             */
            return false;
        } else {
            /* Check for read/extend permissions; deny access for now */
            return true;
        }
    }

    /* The client signer id is same as the current slot signer id; hence it
     * must be allowed full access
     */
    return false;
}

/* TODO: Implement updates for access control strategy here. */
static bool is_read_access_prohibited(uint8_t slot_index)
{
    return false;
}

static inline bool is_measurement_slot_populated(const uint8_t index)
{
    /* Extension is required if any previous measurement value already exists
     * in this slot
     */
    return (measurement_slot[index].is_populated);
}

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
                                            uint8_t *is_locked)
{
    struct measurement_t *src_measurement =
        &measurement_slot[index].measurement;

    if (is_read_access_prohibited(index)) {
        return PSA_ERROR_NOT_PERMITTED;
    }

    if (is_measurement_slot_populated(index)) {
        if ((version_size < src_measurement->metadata.version_size) ||
            (sw_type_size < src_measurement->metadata.sw_type_size) ||
            (signer_id_size < src_measurement->metadata.signer_id_size) ||
            (measurement_value_size < src_measurement->value.hash_buf_size)) {
            /* The size of one of the arguments is incorrect */
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        *signer_id_len = src_measurement->metadata.signer_id_size;
        memcpy(signer_id, src_measurement->metadata.signer_id, *signer_id_len);

        *version_len = src_measurement->metadata.version_size;
        memcpy(version, src_measurement->metadata.version, *version_len);

        *sw_type_len = src_measurement->metadata.sw_type_size;
        memcpy(sw_type, src_measurement->metadata.sw_type, *sw_type_len);

        *measurement_algo = src_measurement->metadata.measurement_algo;

        *measurement_value_len = src_measurement->value.hash_buf_size;
        memcpy(measurement_value, src_measurement->value.hash_buf,
               *measurement_value_len);

        *is_locked = measurement_slot[index].is_locked;
    } else {
        /* Measurement slot is not populated. */
        return PSA_ERROR_DOES_NOT_EXIST;
    }

    return PSA_SUCCESS;
}

static void update_metadata(const uint8_t index,
                            const uint8_t *signer_id,
                            const size_t signer_id_size,
                            const uint8_t *version,
                            const size_t version_size,
                            const uint32_t measurement_algo,
                            const uint8_t *sw_type,
                            const size_t sw_type_size)
{
    struct measurement_metadata_t *dest_metadata =
        &measurement_slot[index].measurement.metadata;

    /* Copy metadata for corresponding measurement slot */
    dest_metadata->signer_id_size = signer_id_size;
    dest_metadata->version_size = version_size;
    dest_metadata->sw_type_size = sw_type_size;

    memcpy(dest_metadata->signer_id, signer_id, signer_id_size);
    memcpy(dest_metadata->version, version, version_size);
    dest_metadata->measurement_algo = measurement_algo;
    memcpy(dest_metadata->sw_type, sw_type, sw_type_size);
}

static void extend_metadata(const uint8_t index)
{
    struct measurement_metadata_t *dest_metadata =
        &measurement_slot[index].measurement.metadata;

    /* Do not update Signer ID as it should be the same */
    /* Do not update Measurement algo as it should be the same */
    /* Clear Version info and Software component description */
    dest_metadata->version_size = 0;
    dest_metadata->sw_type_size = 0;
    (void)memset(dest_metadata->version, 0, VERSION_MAX_SIZE);
    (void)memset(dest_metadata->sw_type, 0, SW_TYPE_MAX_SIZE);
}

static void store_measurement_value(const uint8_t index,
                                    const uint8_t *src_value,
                                    const size_t measurement_size)
{
    memcpy(&measurement_slot[index].measurement.value.hash_buf[0], src_value,
           measurement_size);
    measurement_slot[index].measurement.value.hash_buf_size = measurement_size;
}

static inline void lock_measurement_slot(const uint8_t index)
{
    measurement_slot[index].is_locked = true;
}

static inline void get_stored_measurement_value(const uint8_t index,
                                                uint8_t *output_buffer,
                                                const size_t measurement_size)
{
    memcpy(output_buffer,
           &measurement_slot[index].measurement.value.hash_buf[0],
           MEASUREMENT_VALUE_SIZE);
}

static psa_status_t extend_measurement_value(const uint8_t index,
                                             const uint8_t *measurement,
                                             const size_t measurement_size,
                                             uint8_t *hash_result,
                                             size_t *hash_len)
{
    uint8_t temp_buffer[TEMP_BUFFER_SIZE];
    size_t total_size;

    /* Read previous measurement */
    get_stored_measurement_value(index, temp_buffer, MEASUREMENT_VALUE_SIZE);

    /* concatenate new measurement */
    memcpy(&temp_buffer[MEASUREMENT_VALUE_SIZE], measurement, measurement_size);
    total_size = measurement_size + MEASUREMENT_VALUE_SIZE;

    /* Perform hash calculation */
    return psa_hash_compute(TFM_MEASURED_BOOT_HASH_ALG, temp_buffer,
                              total_size, hash_result, MEASUREMENT_VALUE_SIZE,
                              hash_len);
}

static inline bool is_measurement_slot_locked(const uint8_t index)
{
    return measurement_slot[index].is_locked;
}

static inline void mark_slot_as_occupied(const uint8_t index)
{
    measurement_slot[index].is_populated = true;
}

/* This API is used to extend and store measurement and the corresponding
 * metadata / boot-record (if provided).
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
                                              uint8_t lock_measurement)
{
    psa_status_t status = PSA_SUCCESS;
    uint8_t hash_result[MEASUREMENT_VALUE_SIZE] = {0};
    size_t hash_len;

    log_extend_measurement(index,
                           signer_id, signer_id_size,
                           version, version_size,
                           measurement_algo,
                           sw_type, sw_type_size,
                           measurement_value, measurement_value_size,
                           lock_measurement);

    if (is_slot_access_prohibited(index, signer_id)) {
        status = PSA_ERROR_NOT_PERMITTED;
        goto error;
    }

    if (is_measurement_slot_locked(index)) {
        /* Cannot write to measurement slot once locked */
        status = PSA_ERROR_BAD_STATE;
        goto error;
    }

    /* Check how metadata needs updating for the requested slot */
    if (is_measurement_slot_populated(index)) {
        /* Extend metadata */
        extend_metadata(index);
    } else {
        /* Store the corresponding metadata */
        update_metadata(index,
                        signer_id, signer_id_size,
                        version, version_size,
                        measurement_algo,
                        sw_type, sw_type_size);
        /* Indicate that the slot is not empty anymore */
        mark_slot_as_occupied(index);
    }

    /* Extend current measurement with new measured value */
    status = extend_measurement_value(index,
                                      measurement_value,
                                      measurement_value_size,
                                      hash_result, &hash_len);
    if (status != PSA_SUCCESS) {
        goto error;
    }

    /* Store calculated extended value */
    store_measurement_value(index, hash_result, hash_len);

    if (lock_measurement) {
        /* lock measurement slot if requested */
        lock_measurement_slot(index);
    }

error:
    if (status != PSA_SUCCESS) {
        LOG_DBGFMT("Measured Boot : measurement extension failed.\r\n");
    } else {
        LOG_DBGFMT("Measured Boot : measurement extended successfully.\r\n");
    }

    return status;
}

void initialise_all_measurements(void)
{
    uint32_t i;

    for (i = 0; i < NUM_OF_MEASUREMENT_SLOTS; i++) {
        measurement_slot[i].is_locked = false;
        measurement_slot[i].is_populated = false;
        /* By default, mark all slots as "not common" to avoid accidental extend
         * and write by a different signer id
         */
        measurement_slot[i].is_common = false;

        /* Clear all metadata for corresponding measurement slot */
        (void)memset(&measurement_slot[i].measurement.metadata, 0,
                     sizeof(struct measurement_metadata_t));
        /* Initialise measurement values to default pattern */
        (void)memset(&measurement_slot[i].measurement.value.hash_buf[0],
                     MEASUREMENT_VALUE_INIT_PATTERN,
                     sizeof(measurement_slot[i].measurement.value.hash_buf));
    }
}

#ifdef CONFIG_TFM_BOOT_STORE_MEASUREMENTS
psa_status_t collect_shared_measurements(void)
{
    struct shared_data_tlv_entry tlv_entry;
    struct boot_measurement_metadata *metadata_ptr;
    uint8_t *tlv_end;
    uint8_t *tlv_curr;
    uint8_t claim;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    int32_t rc;

    /* Collect the measurements from the shared data area and store them. */
    rc = tfm_core_get_boot_data(TLV_MAJOR_MBS,
                                (struct tfm_boot_data *)&boot_measurements,
                                sizeof(boot_measurements));
    if (rc != (int32_t)TFM_SUCCESS) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    if (boot_measurements.header.tlv_magic != SHARED_DATA_TLV_INFO_MAGIC) {
        /* Boot measurement information is malformed. */
        return PSA_ERROR_GENERIC_ERROR;
    }

    /* Get the boundaries of TLV section where to lookup. */
    tlv_curr = boot_measurements.data;
    tlv_end = (uint8_t *)&boot_measurements
              + boot_measurements.header.tlv_tot_len;

    while (tlv_curr < tlv_end) {
        /* Copy TLV entry header - the measurement metadata must come first. */
        (void)memcpy(&tlv_entry, tlv_curr, SHARED_DATA_ENTRY_HEADER_SIZE);
        if ((GET_MBS_CLAIM(tlv_entry.tlv_type) != SW_MEASURE_METADATA) ||
            (tlv_entry.tlv_len != sizeof(struct boot_measurement_metadata))) {
            /* Boot measurement information is malformed. */
            status = PSA_ERROR_GENERIC_ERROR;
            break;
        }

        metadata_ptr = (struct boot_measurement_metadata *)
                       (tlv_curr + SHARED_DATA_ENTRY_HEADER_SIZE);

        /* Copy next TLV entry header - it must belong to the measurement. */
        tlv_curr += (SHARED_DATA_ENTRY_HEADER_SIZE + tlv_entry.tlv_len);
        (void)memcpy(&tlv_entry, tlv_curr, SHARED_DATA_ENTRY_HEADER_SIZE);
        claim = GET_MBS_CLAIM(tlv_entry.tlv_type);

        if ((claim != SW_MEASURE_VALUE) &&
            (claim != SW_MEASURE_VALUE_NON_EXTENDABLE)) {
            /* Boot measurement information is malformed. */
            status = PSA_ERROR_GENERIC_ERROR;
            break;
        } else {
            /* Validate size limits of metadata items (if applicable) and
             * the size limits of measurement value before storing it.
             */
            if ((metadata_ptr->signer_id_size < SIGNER_ID_MIN_SIZE) ||
                (metadata_ptr->signer_id_size > SIGNER_ID_MAX_SIZE) ||
                (tlv_entry.tlv_len < MEASUREMENT_VALUE_MIN_SIZE)    ||
                (tlv_entry.tlv_len > MEASUREMENT_VALUE_MAX_SIZE)) {
                status = PSA_ERROR_GENERIC_ERROR;
                break;
            }

            /* Store the measurement and associated metadata. */
            status = measured_boot_extend_measurement(
                    (uint8_t)GET_MBS_SLOT(tlv_entry.tlv_type),
                    metadata_ptr->signer_id,
                    metadata_ptr->signer_id_size,
                    (const uint8_t*)metadata_ptr->sw_version,
                    tfm_strnlen(metadata_ptr->sw_version,
                                sizeof(metadata_ptr->sw_version)),
                    metadata_ptr->measurement_type,
                    (const uint8_t*)metadata_ptr->sw_type,
                    tfm_strnlen(metadata_ptr->sw_type,
                                sizeof(metadata_ptr->sw_type)),
                    tlv_curr + SHARED_DATA_ENTRY_HEADER_SIZE,
                    tlv_entry.tlv_len,
                    (claim == SW_MEASURE_VALUE_NON_EXTENDABLE) ? true : false);
            if (status != PSA_SUCCESS) {
                /* Failed to store measurement. */
                break;
            }
        }
        /* Move to the next TLV entry. */
        tlv_curr += (SHARED_DATA_ENTRY_HEADER_SIZE + tlv_entry.tlv_len);
    }

    return status;
}
#endif /* CONFIG_TFM_BOOT_STORE_MEASUREMENTS */
