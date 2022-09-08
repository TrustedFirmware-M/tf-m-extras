/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "measured_boot_common.h"
#include "test_values.h"
#include <string.h>
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"

struct test_measurement_data_t input_test_data[TEST_DATA_COUNT] = {
    {
    .slot_index = TEST_1001_SLOT_INDEX,
    .measurement_algo = PSA_ALG_SHA_256,
    .signer_id = TEST_VALUE_SIGNER_ID,
    .version = TEST_VALUE_SW_VERSION,
    .sw_type = TEST_VALUE_SW_MEASUREMENT_DESC,
    .hash_buf = {(uint8_t[]){SW_SHA256_VAL_TEST_0}, SHA256_SIZE},
    },
    {
    .slot_index = TEST_1001_SLOT_INDEX,
    .measurement_algo = PSA_ALG_SHA_256,
    .signer_id = TEST_VALUE_SIGNER_ID,
    .version = TEST_VALUE_SW_VERSION,
    .sw_type = TEST_VALUE_SW_MEASUREMENT_DESC,
    .hash_buf = {(uint8_t[]){SW_SHA256_VAL_TEST_1}, SHA256_SIZE},
    },
    {
    .slot_index = TEST_1002_SLOT_INDEX,
    .measurement_algo = PSA_ALG_SHA_512,
    .signer_id = TEST_VALUE_SIGNER_ID,
    .version = TEST_VALUE_SW_VERSION,
    .sw_type = TEST_VALUE_SW_MEASUREMENT_DESC,
    .hash_buf = {(uint8_t[]){SW_SHA512_VAL_TEST_2}, SHA512_SIZE},
    },
    {
    .slot_index = TEST_1002_SLOT_INDEX,
    .measurement_algo = PSA_ALG_SHA_512,
    .signer_id = TEST_VALUE_SIGNER_ID,
    .version = TEST_VALUE_SW_VERSION,
    .sw_type = TEST_VALUE_SW_MEASUREMENT_DESC,
    .hash_buf = {(uint8_t[]){SW_SHA512_VAL_TEST_3}, SHA512_SIZE},
    },
};

#if MEASUREMENT_VALUE_SIZE == 32
struct test_measurement_data_t expected_test_data[TEST_DATA_COUNT] = {
    {
    .slot_index = TEST_1001_SLOT_INDEX,
    .measurement_algo = PSA_ALG_SHA_256,
    .signer_id = TEST_VALUE_SIGNER_ID,
    .version = TEST_VALUE_SW_VERSION,
    .sw_type = TEST_VALUE_SW_MEASUREMENT_DESC,
    .hash_buf = {(uint8_t[]){EXPECTED_SHA256_MEASUREMENT_VAL_TEST_0},
                 SHA256_SIZE},
    },
    {
    .slot_index = TEST_1001_SLOT_INDEX,
    .measurement_algo = PSA_ALG_SHA_256,
    .signer_id = TEST_VALUE_SIGNER_ID,
    .version = TEST_VALUE_ZERO,
    .sw_type = TEST_VALUE_ZERO,
    .hash_buf = {(uint8_t[]){EXPECTED_SHA256_MEASUREMENT_VAL_TEST_1},
                 SHA256_SIZE},
    },
    {
    .slot_index = TEST_1002_SLOT_INDEX,
    .measurement_algo = PSA_ALG_SHA_512,
    .signer_id = TEST_VALUE_SIGNER_ID,
    .version = TEST_VALUE_SW_VERSION,
    .sw_type = TEST_VALUE_SW_MEASUREMENT_DESC,
    .hash_buf = {(uint8_t[]){EXPECTED_SHA256_MEASUREMENT_VAL_TEST_2},
                 SHA256_SIZE},
    },
    {
    .slot_index = TEST_1002_SLOT_INDEX,
    .measurement_algo = PSA_ALG_SHA_512,
    .signer_id = TEST_VALUE_SIGNER_ID,
    .version = TEST_VALUE_ZERO,
    .sw_type = TEST_VALUE_ZERO,
    .hash_buf = {(uint8_t[]){EXPECTED_SHA256_MEASUREMENT_VAL_TEST_3},
                 SHA256_SIZE},
    },
};
#elif MEASUREMENT_VALUE_SIZE == 64
struct test_measurement_data_t expected_test_data[TEST_DATA_COUNT] = {
    {
    .slot_index = TEST_1001_SLOT_INDEX,
    .measurement_algo = PSA_ALG_SHA_256,
    .signer_id = TEST_VALUE_SIGNER_ID,
    .version = TEST_VALUE_SW_VERSION,
    .sw_type = TEST_VALUE_SW_MEASUREMENT_DESC,
    .hash_buf = {(uint8_t[]){EXPECTED_SHA512_MEASUREMENT_VAL_TEST_0},
                 SHA512_SIZE},
    },
    {
    .slot_index = TEST_1001_SLOT_INDEX,
    .measurement_algo = PSA_ALG_SHA_256,
    .signer_id = TEST_VALUE_SIGNER_ID,
    .version = TEST_VALUE_ZERO,
    .sw_type = TEST_VALUE_ZERO,
    .hash_buf = {(uint8_t[]){EXPECTED_SHA512_MEASUREMENT_VAL_TEST_1},
                 SHA512_SIZE},
    },
    {
    .slot_index = TEST_1002_SLOT_INDEX,
    .measurement_algo = PSA_ALG_SHA_512,
    .signer_id = TEST_VALUE_SIGNER_ID,
    .version = TEST_VALUE_SW_VERSION,
    .sw_type = TEST_VALUE_SW_MEASUREMENT_DESC,
    .hash_buf = {(uint8_t[]){EXPECTED_SHA512_MEASUREMENT_VAL_TEST_2},
                 SHA512_SIZE},
    },
    {
    .slot_index = TEST_1002_SLOT_INDEX,
    .measurement_algo = PSA_ALG_SHA_512,
    .signer_id = TEST_VALUE_SIGNER_ID,
    .version = TEST_VALUE_ZERO,
    .sw_type = TEST_VALUE_ZERO,
    .hash_buf = {(uint8_t[]){EXPECTED_SHA512_MEASUREMENT_VAL_TEST_3},
                 SHA512_SIZE},
    },
};
#else
#error "Unknown hash algorithm"
#endif

/*
 * Public function. See measured_boot_common.h
 */
void load_test_measurement_data(struct test_measurement_data_t *test_data_ptr,
                                struct measurement_t *measurement,
                                uint8_t *slot_index)
{
    *slot_index = test_data_ptr->slot_index;

    memset(measurement, 0, sizeof(*measurement));
    measurement->metadata.measurement_algo = test_data_ptr->measurement_algo;

    memcpy((uint8_t *)measurement->metadata.signer_id,
           (uint8_t *)test_data_ptr->signer_id.ptr,
           test_data_ptr->signer_id.len);
    measurement->metadata.signer_id_size = test_data_ptr->signer_id.len;

    memcpy((uint8_t *)measurement->metadata.version,
           (uint8_t *)test_data_ptr->version.ptr,
           test_data_ptr->version.len);
    measurement->metadata.version_size = test_data_ptr->version.len;

    memcpy((uint8_t *)measurement->metadata.sw_type,
           (uint8_t *)test_data_ptr->sw_type.ptr,
           test_data_ptr->sw_type.len);
    measurement->metadata.sw_type_size = test_data_ptr->sw_type.len;

    memcpy((uint8_t *)measurement->value.hash_buf,
           (uint8_t *)test_data_ptr->hash_buf.ptr,
           test_data_ptr->hash_buf.len);
    measurement->value.hash_buf_size = test_data_ptr->hash_buf.len;
}

/*
 * Public function. See measured_boot_common.h
 */
void load_default_valid_test_data(struct measurement_t *measurement)
{
    struct test_buf_t tmp;
    struct test_buf_t default_sha_value =
        {(uint8_t[]){SW_SHA256_VAL_TEST_0}, SHA256_SIZE};

    memset(measurement, 0, sizeof(struct measurement_t));

    tmp = TEST_VALUE_SIGNER_ID;
    memcpy((uint8_t *)measurement->metadata.signer_id, (uint8_t *)tmp.ptr,
           tmp.len);
    measurement->metadata.signer_id_size = tmp.len;

    measurement->metadata.measurement_algo = MEASURED_BOOT_HASH_ALG;

    tmp = TEST_VALUE_SW_VERSION;
    memcpy((uint8_t *)measurement->metadata.version, (uint8_t *)tmp.ptr,
           tmp.len);
    measurement->metadata.version_size = tmp.len;

    tmp = TEST_VALUE_SW_MEASUREMENT_DESC;
    memcpy((uint8_t *)measurement->metadata.sw_type, (uint8_t *)tmp.ptr,
           tmp.len);
    measurement->metadata.sw_type_size = tmp.len;

    memcpy((uint8_t *)measurement->value.hash_buf,
           (uint8_t *)default_sha_value.ptr, default_sha_value.len);
    measurement->value.hash_buf_size = default_sha_value.len;
}

/*
 * Public function. See measured_boot_common.h
 */
psa_status_t extend_measurement(uint8_t slot_index,
                                struct measurement_t *measurement,
                                bool lock_measurement)
{
    return tfm_measured_boot_extend_measurement(
                                    slot_index,
                                    &measurement->metadata.signer_id[0],
                                    measurement->metadata.signer_id_size,
                                    &measurement->metadata.version[0],
                                    measurement->metadata.version_size,
                                    measurement->metadata.measurement_algo,
                                    &measurement->metadata.sw_type[0],
                                    measurement->metadata.sw_type_size,
                                    &measurement->value.hash_buf[0],
                                    measurement->value.hash_buf_size,
                                    lock_measurement);
}

/*
 * Public function. See measured_boot_common.h
 */
void initialise_measurement(struct measurement_t *measurement)
{
    (void)memset(measurement, 0, (sizeof(struct measurement_t)));
    measurement->value.hash_buf_size = MEASUREMENT_VALUE_MAX_SIZE;
    measurement->metadata.signer_id_size = SIGNER_ID_MAX_SIZE;
    measurement->metadata.version_size = VERSION_MAX_SIZE;
    measurement->metadata.sw_type_size = SW_TYPE_MAX_SIZE;
    measurement->metadata.measurement_algo = MEASURED_BOOT_HASH_ALG;
}

/*
 * Public function. See measured_boot_common.h
 */
psa_status_t read_measurement(uint8_t slot_index,
                              struct measurement_t *measurement,
                              bool *is_locked)
{
    psa_status_t status;
    size_t signer_id_len, version_len, sw_type_len;
    size_t measurement_value_len;

    status = tfm_measured_boot_read_measurement(
                                    slot_index,
                                    &measurement->metadata.signer_id[0],
                                    measurement->metadata.signer_id_size,
                                    &signer_id_len,
                                    &measurement->metadata.version[0],
                                    measurement->metadata.version_size,
                                    &version_len,
                                    &measurement->metadata.measurement_algo,
                                    &measurement->metadata.sw_type[0],
                                    measurement->metadata.sw_type_size,
                                    &sw_type_len,
                                    &measurement->value.hash_buf[0],
                                    measurement->value.hash_buf_size,
                                    &measurement_value_len,
                                    is_locked);

    /* update to reflect correct sizes */
    measurement->metadata.signer_id_size = signer_id_len;
    measurement->metadata.version_size = version_len;
    measurement->metadata.sw_type_size = sw_type_len;
    measurement->value.hash_buf_size = measurement_value_len;

    return status;
}
