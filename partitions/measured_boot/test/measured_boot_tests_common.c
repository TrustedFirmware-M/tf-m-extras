/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "measured_boot_tests_common.h"
#include "measured_boot_common.h"
#include <string.h>
#include "test_values.h"

extern struct test_measurement_data_t input_test_data[TEST_DATA_COUNT];
extern struct test_measurement_data_t expected_test_data[TEST_DATA_COUNT];

static psa_status_t run_core_functionality_test(uint8_t test_data_array_index)
{
    psa_status_t status;
    struct measurement_t input_measurement, output_measurement;
    struct measurement_t expected_measurement;
    bool is_locked;
    uint8_t slot_index;
    int rc;

    /* Clear all buffers */
    (void)memset(&input_measurement, 0, (sizeof(struct measurement_t)));
    (void)memset(&expected_measurement, 0, (sizeof(struct measurement_t)));

    /* Load test measurement and metadata values */
    load_test_measurement_data(&input_test_data[test_data_array_index],
                               &input_measurement,
                               &slot_index);
    /* Load expected measurement and metadata values */
    load_test_measurement_data(&expected_test_data[test_data_array_index],
                               &expected_measurement,
                               &slot_index);


    /* Request to extend and store loaded test metadata & measurement values */
    status = extend_measurement(slot_index, &input_measurement, false);
    if (status != PSA_SUCCESS) {
        return status;
    }

    initialise_measurement(&output_measurement);
    status = read_measurement(slot_index, &output_measurement, &is_locked);
    if (status != PSA_SUCCESS) {
        return status;
    }

    rc = memcmp((uint8_t *)&output_measurement,
                (uint8_t *)&expected_measurement,
                sizeof(struct measurement_t));
    if (rc != 0) {
        return PSA_ERROR_SERVICE_FAILURE;
    }

    return status;
}

/*
 * Public function. See measured_boot_tests_common.h
 */
void tfm_measured_boot_test_common_001(struct test_result_t *ret)
{
    psa_status_t status;

    status = run_core_functionality_test(0);
    if (status != PSA_SUCCESS) {
        TEST_FAIL("Extend/Read measurement with input SHA256 value - Part1 "
                  "should not fail");
        return;
    }

    status = run_core_functionality_test(1);
    if (status != PSA_SUCCESS) {
        TEST_FAIL("Extend/Read measurement with input SHA256 value - Part2 "
                  "should not fail");
        return;
    }

    ret->val = TEST_PASSED;
}

/*
 * Public function. See measured_boot_tests_common.h
 */
void tfm_measured_boot_test_common_002(struct test_result_t *ret)
{
    psa_status_t status;

    status = run_core_functionality_test(2);
    if (status != PSA_SUCCESS) {
        TEST_FAIL("Extend/Read measurement with input SHA512 value - Part1 "
                  "should not fail");
        return;
    }

    status = run_core_functionality_test(3);
    if (status != PSA_SUCCESS) {
        TEST_FAIL("Extend/Read measurement with input SHA512 value - Part2 "
                  "should not fail");
        return;
    }

    ret->val = TEST_PASSED;
}

/*
 * Public function. See measured_boot_tests_common.h
 */
void tfm_measured_boot_test_common_003(struct test_result_t *ret)
{
    psa_status_t status;
    struct measurement_t measurement, output_measurement;
    bool is_locked;
    /* Set invalid slot_index */
    uint8_t slot_index = TEST_1003_SLOT_INDEX;

    /* Load test measurement and metadata values */
    load_default_valid_test_data(&measurement);

    status = extend_measurement(slot_index, &measurement, false);
    if (status != PSA_ERROR_INVALID_ARGUMENT) {
        TEST_FAIL("Extend measurement should fail with invalid slot_index");
        return;
    }

    initialise_measurement(&output_measurement);
    status = read_measurement(slot_index, &output_measurement, &is_locked);
    if (status != PSA_ERROR_INVALID_ARGUMENT) {
        TEST_FAIL("Read measurement should fail with invalid slot_index");
        return;
    }

    ret->val = TEST_PASSED;
}

/*
 * Public function. See measured_boot_tests_common.h
 */
void tfm_measured_boot_test_common_004(struct test_result_t *ret)
{
    psa_status_t status;
    struct measurement_t measurement;
    uint8_t slot_index = TEST_1004_SLOT_INDEX;

    /* Load test measurement and metadata values */
    load_default_valid_test_data(&measurement);
    /* Set invalid larger measurement value size */
    measurement.value.hash_buf_size = MEASUREMENT_VALUE_MAX_SIZE + 1;

    status = extend_measurement(slot_index, &measurement, false);
    if (status != PSA_ERROR_INVALID_ARGUMENT) {
        TEST_FAIL("Extend measurement should fail with invalid larger"
                  "measurement value size");
        return;
    }

    /* Set invalid smaller measurement value size */
    measurement.value.hash_buf_size = 1;
    status = extend_measurement(slot_index, &measurement, false);
    if (status != PSA_ERROR_INVALID_ARGUMENT) {
        TEST_FAIL("Extend measurement should fail with invalid larger"
                  "measurement value size");
        return;
    }

    ret->val = TEST_PASSED;
}

/*
 * Public function. See measured_boot_tests_common.h
 */
void tfm_measured_boot_test_common_005(struct test_result_t *ret)
{
    psa_status_t status;
    struct measurement_t measurement;
    bool is_locked;
    uint8_t slot_index = TEST_1005_SLOT_INDEX;

    /* Load test measurement and metadata values */
    load_default_valid_test_data(&measurement);

    status = extend_measurement(slot_index, &measurement, false);
    if (status != PSA_SUCCESS) {
        TEST_FAIL("Extend measurement should not fail with valid "
                  "measurement value size");
        return;
    }

    /* Set invalid smaller measurement value size */
    measurement.value.hash_buf_size =  measurement.value.hash_buf_size - 1;

    status = read_measurement(slot_index, &measurement, &is_locked);
    if (status != PSA_ERROR_INVALID_ARGUMENT) {
        TEST_FAIL("Read measurement should fail with invalid input"
                  "measurement value buffer size");
        return;
    }

    ret->val = TEST_PASSED;
}

/*
 * Public function. See measured_boot_tests_common.h
 */
void tfm_measured_boot_test_common_006(struct test_result_t *ret)
{
    psa_status_t status;
    struct measurement_t measurement;
    uint8_t slot_index = TEST_1006_SLOT_INDEX;

    /* Load test measurement and metadata values */
    load_default_valid_test_data(&measurement);

    /* Set invalid input larger signer id size */
    measurement.metadata.signer_id_size = SIGNER_ID_MAX_SIZE + 1;

    status = extend_measurement(slot_index, &measurement, false);
    if (status != PSA_ERROR_INVALID_ARGUMENT) {
        TEST_FAIL("Extend measurement should fail with invalid larger"
                  "signer id size");
        return;
    }

    /* Set invalid input smaller signer id size */
    measurement.metadata.signer_id_size = SIGNER_ID_MIN_SIZE - 1;

    status = extend_measurement(slot_index, &measurement, false);
    if (status != PSA_ERROR_INVALID_ARGUMENT) {
        TEST_FAIL("Extend measurement should fail with invalid smaller"
                  "signer id size");
        return;
    }

    ret->val = TEST_PASSED;
}

/*
 * Public function. See measured_boot_tests_common.h
 */
void tfm_measured_boot_test_common_007(struct test_result_t *ret)
{
    psa_status_t status;
    struct measurement_t measurement;
    bool is_locked;
    uint8_t slot_index = TEST_1007_SLOT_INDEX;

    /* Load test measurement and metadata values */
    load_default_valid_test_data(&measurement);

    status = extend_measurement(slot_index, &measurement, false);
    if (status != PSA_SUCCESS) {
        TEST_FAIL("Extend measurement should not fail with valid "
                  "signer id size");
        return;
    }

    /* Set invalid input smaller signer id size */
    measurement.metadata.signer_id_size =
                                        measurement.metadata.signer_id_size - 1;

    status = read_measurement(slot_index, &measurement, &is_locked);
    if (status != PSA_ERROR_INVALID_ARGUMENT) {
        TEST_FAIL("Read measurement should fail with invalid signer id"
                  "buffer size");
        return;
    }

    ret->val = TEST_PASSED;
}

/*
 * Public function. See measured_boot_tests_common.h
 */
void tfm_measured_boot_test_common_008(struct test_result_t *ret)
{
    psa_status_t status;
    struct measurement_t measurement;
    uint8_t slot_index = TEST_1008_SLOT_INDEX;

    /* Load test measurement and metadata values */
    load_default_valid_test_data(&measurement);

    /* Set invalid input larger version size */
    measurement.metadata.version_size = VERSION_MAX_SIZE + 1;

    status = extend_measurement(slot_index, &measurement, false);
    if (status != PSA_ERROR_INVALID_ARGUMENT) {
        TEST_FAIL("Extend measurement should fail with invalid larger"
                  "version size");
        return;
    }

    ret->val = TEST_PASSED;
}

/*
 * Public function. See measured_boot_tests_common.h
 */
void tfm_measured_boot_test_common_009(struct test_result_t *ret)
{
    psa_status_t status;
    struct measurement_t measurement;
    bool is_locked;
    uint8_t slot_index = TEST_1009_SLOT_INDEX;

    /* Load test measurement and metadata values */
    load_default_valid_test_data(&measurement);

    status = extend_measurement(slot_index, &measurement, false);
    if (status != PSA_SUCCESS) {
        TEST_FAIL("Extend measurement should not fail with valid version size");
        return;
    }

    /* Set invalid input smaller version buffer size */
    measurement.metadata.version_size = measurement.metadata.version_size - 1;

    status = read_measurement(slot_index, &measurement, &is_locked);
    if (status != PSA_ERROR_INVALID_ARGUMENT) {
        TEST_FAIL("Read measurement should fail with invalid version"
                  "buffer size");
        return;
    }

    ret->val = TEST_PASSED;
}

/*
 * Public function. See measured_boot_tests_common.h
 */
void tfm_measured_boot_test_common_010(struct test_result_t *ret)
{
    psa_status_t status;
    struct measurement_t measurement;
    uint8_t slot_index = TEST_1010_SLOT_INDEX;

    /* Load test measurement and metadata values */
    load_default_valid_test_data(&measurement);

    /* Set invalid input larger software type size */
    measurement.metadata.sw_type_size = SW_TYPE_MAX_SIZE + 1;

    status = extend_measurement(slot_index, &measurement, false);
    if (status != PSA_ERROR_INVALID_ARGUMENT) {
        TEST_FAIL("Extend measurement should fail with invalid larger"
                  "software type size");
        return;
    }

    ret->val = TEST_PASSED;
}

/*
 * Public function. See measured_boot_tests_common.h
 */
void tfm_measured_boot_test_common_011(struct test_result_t *ret)
{
    psa_status_t status;
    struct measurement_t measurement;
    bool is_locked;
    uint8_t slot_index = TEST_1011_SLOT_INDEX;

    /* Load test measurement and metadata values */
    load_default_valid_test_data(&measurement);

    status = extend_measurement(slot_index, &measurement, false);
    if (status != PSA_SUCCESS) {
        TEST_FAIL("Extend measurement should not fail with valid sw_type size");
        return;
    }

    /* Set invalid input smaller software type size */
    measurement.metadata.sw_type_size = measurement.metadata.sw_type_size - 1;

    status = read_measurement(slot_index, &measurement, &is_locked);
    if (status != PSA_ERROR_INVALID_ARGUMENT) {
        TEST_FAIL("Read measurement should fail with invalid smaller"
                  "software type buffer size");
        return;
    }

    ret->val = TEST_PASSED;
}

/*
 * Public function. See measured_boot_tests_common.h
 */
void tfm_measured_boot_test_common_012(struct test_result_t *ret)
{
    psa_status_t status;
    uint8_t slot_index;
    struct measurement_t measurement;

    /* Load test measurement and metadata values */
    load_default_valid_test_data(&measurement);
    slot_index = TEST_1012_SLOT_INDEX;

    status = extend_measurement(slot_index, &measurement, true);
    if (status != PSA_SUCCESS) {
        TEST_FAIL("Extend measurement unlock test - part1 should not fail");
        return;
    }

    status = extend_measurement(slot_index, &measurement, false);
    if (status != PSA_ERROR_BAD_STATE) {
        TEST_FAIL("Extend measurement shall not unlock once slot is locked");
        return;
    }

    ret->val = TEST_PASSED;
}

/*
 * Public function. See measured_boot_tests_common.h
 */
void tfm_measured_boot_test_common_013(struct test_result_t *ret)
{
    psa_status_t status;
    struct measurement_t measurement;
    uint8_t slot_index = TEST_1013_SLOT_INDEX;

    /* Load test measurement and metadata values */
    load_default_valid_test_data(&measurement);

    status = extend_measurement(slot_index, &measurement, false);
    if (status != PSA_SUCCESS) {
        TEST_FAIL("Extend measurement should not fail");
        return;
    }

    /* Try to extend using different value of signer id for same slot */
    measurement.metadata.signer_id[0] = 0xFF;
    status = extend_measurement(slot_index, &measurement, false);
    if (status != PSA_ERROR_NOT_PERMITTED) {
        TEST_FAIL("Extend measurement should fail with different "
                  "signer id");
        return;
    }
}
