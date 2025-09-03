/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 */

#include "mcuboot_test_helpers.h"
#include "rse_image_verification_defs.h"
#include "st_test_helpers.h"
#include "stdint.h"
#include "test_framework.h"
#include <stdbool.h>

extern uint8_t test_mcuboot_signed_image[];

static void tfm_riv_test_1001(struct test_result_t *ret);
static void tfm_riv_test_1002(struct test_result_t *ret);
static void tfm_riv_test_1003(struct test_result_t *ret);
static void tfm_riv_test_1004(struct test_result_t *ret);
static void tfm_riv_test_1005(struct test_result_t *ret);
static void tfm_riv_test_1006(struct test_result_t *ret);
static void tfm_riv_test_1007(struct test_result_t *ret);
static void tfm_riv_test_1008(struct test_result_t *ret);
static void tfm_riv_test_1009(struct test_result_t *ret);
static void tfm_riv_test_1010(struct test_result_t *ret);
static void tfm_riv_test_1011(struct test_result_t *ret);
static void tfm_riv_test_1012(struct test_result_t *ret);

static struct test_t riv_s_tests[] = {
    {&tfm_riv_test_1001, "TFM_RIV_TEST_1001",
     "RSE Image Verification MCUBoot signature verification success"},
    {&tfm_riv_test_1002, "TFM_RIV_TEST_1002",
     "RSE Image Verification MCUBoot rejection due to bad signature"},
    {&tfm_riv_test_1003, "TFM_RIV_TEST_1003",
     "RSE Image Verification MCUBoot rejection due to bad pub key"},
    {&tfm_riv_test_1004, "TFM_RIV_TEST_1004",
     "RSE Image Verification ST signature verification"},
    {&tfm_riv_test_1005, "TFM_RIV_TEST_1005",
     "RSE Image Verification ST verification rejection due to bad "
     "signature"},
    {&tfm_riv_test_1006, "TFM_RIV_TEST_1006",
     "RSE Image Verification ST verification rejection due to bad pub key"},
    {&tfm_riv_test_1007, "TFM_RIV_TEST_1007",
     "RSE Image Verification ST verification rejection due to bad image "
     "hash"},
    {&tfm_riv_test_1008, "TFM_RIV_TEST_1008",
     "RSE Image Verification MCUBoot signature verification with "
     "multi-chain"},
    {&tfm_riv_test_1009, "TFM_RIV_TEST_1009",
     "RSE Image Verification MCUBoot rejection due to bad NV counter"},
    {&tfm_riv_test_1010, "TFM_RIV_TEST_1010",
     "RSE Image Verification MCUBoot might-be-signed image verification "
     "success"},
    {&tfm_riv_test_1011, "TFM_RIV_TEST_1011",
     "RSE Image Verification MCUBoot 0 chain image verification success"},
    {&tfm_riv_test_1012, "TFM_RIV_TEST_1012",
     "RSE Image Verification bad verification structure length"},
};

void register_testsuite_extra_s_interface(struct test_suite_t *p_test_suite)
{
    uint32_t list_size = sizeof(riv_s_tests) / sizeof(riv_s_tests[0]);

    set_testsuite("RSE Image Verification Secure Tests (TFM_RIV_TEST_1XXX)",
                  riv_s_tests, list_size, p_test_suite);
}

static void tfm_riv_test_1001(struct test_result_t *ret)
{
    struct rse_image_verification_boot_measurement_t boot_measurement = {0};
    struct riv_mcuboot_test_config config = {
        .corrupt_signature = false,
        .corrupt_public_key = false,
        .num_chains = 1,
        .bad_nv_counter = false,
        .must_be_signed = true,
        .corrupt_verification_structure = false,
        .expected_ret_val = RSE_VERIFICATION_SERVICE_SUCCESS};

    execute_mcuboot_test(ret, &config, &boot_measurement);

    /*
     * The value.hash_buf_size and metadata.signed_id_size must be
     * changed by the RIV partition on a successful verification. There
     * is no additional signer in the MCUBoot test image so that should
     * be 0.
     */
    if (ret->val == TEST_PASSED) {
        if (boot_measurement.measurement.value.hash_buf_size == 0 ||
            boot_measurement.measurement.metadata.signer_id_size == 0 ||
            boot_measurement.measurement.metadata.additional_signer_amount != 0) {
            ret->val = TEST_FAILED;
        }
    }
}

static void tfm_riv_test_1002(struct test_result_t *ret)
{
    struct rse_image_verification_boot_measurement_t boot_measurement = {0};
    struct riv_mcuboot_test_config config = {
        .corrupt_signature = true,
        .corrupt_public_key = false,
        .num_chains = 1,
        .bad_nv_counter = false,
        .must_be_signed = true,
        .corrupt_verification_structure = false,
        .expected_ret_val = RSE_VERIFICATION_SERVICE_ERR_VERIFICATION_FAILED};

    execute_mcuboot_test(ret, &config, &boot_measurement);

    /*
     * The verification failed so the measurement data should not be updated
     */
    if (ret->val == TEST_PASSED) {
        if (boot_measurement.measurement.value.hash_buf_size != 0 ||
            boot_measurement.measurement.metadata.signer_id_size != 0) {
            ret->val = TEST_FAILED;
        }
    }
}

static void tfm_riv_test_1003(struct test_result_t *ret)
{
    struct rse_image_verification_boot_measurement_t boot_measurement = {0};
    struct riv_mcuboot_test_config config = {
        .corrupt_signature = false,
        .corrupt_public_key = true,
        .num_chains = 1,
        .bad_nv_counter = false,
        .must_be_signed = true,
        .corrupt_verification_structure = false,
        .expected_ret_val = RSE_VERIFICATION_SERVICE_ERR_BAD_KEY};

    execute_mcuboot_test(ret, &config, &boot_measurement);

    /*
     * The verification failed so the measurement data should not be updated
     */
    if (ret->val == TEST_PASSED) {
        if (boot_measurement.measurement.value.hash_buf_size != 0 ||
            boot_measurement.measurement.metadata.signer_id_size != 0) {
            ret->val = TEST_FAILED;
        }
    }
}

static void tfm_riv_test_1004(struct test_result_t *ret)
{
    struct rse_image_verification_boot_measurement_t boot_measurement = {0};
    struct riv_st_test_config config = {.corrupt_signature = false,
                                        .corrupt_public_key = false,
                                        .corrupt_image_hash = false,
                                        .num_chains = 1,
                                        .expected_ret_val =
                                            RSE_VERIFICATION_SERVICE_SUCCESS};

    execute_st_test(ret, &config, &boot_measurement);

    /*
     * The value.hash_buf_size and metadata.signed_id_size must be
     * changed by the RIV partition on a successful verification. There
     * is no additional signer in the ST test image so that should
     * be 0.
     */
    if (ret->val == TEST_PASSED) {
        if (boot_measurement.measurement.value.hash_buf_size == 0 ||
            boot_measurement.measurement.metadata.signer_id_size == 0 ||
            boot_measurement.measurement.metadata.additional_signer_amount != 0) {
            ret->val = TEST_FAILED;
        }
    }
}

static void tfm_riv_test_1005(struct test_result_t *ret)
{
    struct rse_image_verification_boot_measurement_t boot_measurement = {0};
    struct riv_st_test_config config = {
        .corrupt_signature = true,
        .corrupt_public_key = false,
        .corrupt_image_hash = false,
        .num_chains = 1,
        .expected_ret_val = RSE_VERIFICATION_SERVICE_ERR_VERIFICATION_FAILED};

    execute_st_test(ret, &config, &boot_measurement);

    /*
     * The verification failed so the measurement data should not be updated
     */
    if (ret->val == TEST_PASSED) {
        if (boot_measurement.measurement.value.hash_buf_size != 0 ||
            boot_measurement.measurement.metadata.signer_id_size != 0) {
            ret->val = TEST_FAILED;
        }
    }
}

static void tfm_riv_test_1006(struct test_result_t *ret)
{
    struct rse_image_verification_boot_measurement_t boot_measurement = {0};
    struct riv_st_test_config config = {
        .corrupt_signature = false,
        .corrupt_public_key = true,
        .corrupt_image_hash = false,
        .num_chains = 1,
        .expected_ret_val = RSE_VERIFICATION_SERVICE_ERR_VERIFICATION_FAILED};

    execute_st_test(ret, &config, &boot_measurement);
    /*
     * The verification failed so the measurement data should not be updated
     */
    if (ret->val == TEST_PASSED) {
        if (boot_measurement.measurement.value.hash_buf_size != 0 ||
            boot_measurement.measurement.metadata.signer_id_size != 0) {
            ret->val = TEST_FAILED;
        }
    }
}

static void tfm_riv_test_1007(struct test_result_t *ret)
{
    struct rse_image_verification_boot_measurement_t boot_measurement = {0};
    struct riv_st_test_config config = {
        .corrupt_signature = false,
        .corrupt_public_key = false,
        .corrupt_image_hash = true,
        .num_chains = 1,
        .expected_ret_val = RSE_VERIFICATION_SERVICE_ERR_VERIFICATION_FAILED};

    execute_st_test(ret, &config, &boot_measurement);

    /*
     * The verification failed so the measurement data should not be updated
     */
    if (ret->val == TEST_PASSED) {
        if (boot_measurement.measurement.value.hash_buf_size != 0 ||
            boot_measurement.measurement.metadata.signer_id_size != 0) {
            ret->val = TEST_FAILED;
        }
    }
}

static void tfm_riv_test_1008(struct test_result_t *ret)
{
    struct rse_image_verification_boot_measurement_t boot_measurement[2] = {0};

    struct riv_mcuboot_test_config config = {
        .corrupt_signature = false,
        .corrupt_public_key = false,
        .num_chains = 2,
        .bad_nv_counter = false,
        .must_be_signed = true,
        .corrupt_verification_structure = false,
        .expected_ret_val = RSE_VERIFICATION_SERVICE_SUCCESS};

    execute_mcuboot_test(ret, &config, boot_measurement);

    /*
     * The value.hash_buf_size and metadata.signed_id_size must be
     * changed by the RIV partition on a successful verification. There
     * is no additional signer in the MCUBoot test image so that should
     * be 0.
     */
    if (ret->val == TEST_PASSED) {
        for (uint32_t i = 0; i < 2; i++) {
            if (boot_measurement[i].measurement.value.hash_buf_size == 0 ||
                boot_measurement[i].measurement.metadata.signer_id_size == 0 ||
                boot_measurement[i]
                        .measurement.metadata.additional_signer_amount != 0) {
                ret->val = TEST_FAILED;
            }
        }
    }
}

static void tfm_riv_test_1009(struct test_result_t *ret)
{
    struct rse_image_verification_boot_measurement_t boot_measurement = {0};
    struct riv_mcuboot_test_config config = {
        .corrupt_signature = false,
        .corrupt_public_key = false,
        .num_chains = 1,
        .bad_nv_counter = true,
        .must_be_signed = true,
        .corrupt_verification_structure = false,
        .expected_ret_val = RSE_VERIFICATION_SERVICE_ERR_NV_COUNTER};

    execute_mcuboot_test(ret, &config, &boot_measurement);

    /*
     * The verification failed so the measurement data should not be updated
     */
    if (ret->val == TEST_PASSED) {
        if (boot_measurement.measurement.value.hash_buf_size != 0 ||
            boot_measurement.measurement.metadata.signer_id_size != 0) {
            ret->val = TEST_FAILED;
        }
    }
}

static void tfm_riv_test_1010(struct test_result_t *ret)
{
    struct rse_image_verification_boot_measurement_t boot_measurement = {0};
    struct riv_mcuboot_test_config config = {
        .corrupt_signature = false,
        .corrupt_public_key = true,
        .num_chains = 1,
        .bad_nv_counter = false,
        .must_be_signed = false,
        .expected_ret_val = RSE_VERIFICATION_SERVICE_SUCCESS};

    execute_mcuboot_test(ret, &config, &boot_measurement);

    /*
     * The verification failed so the measurement data should not be updated
     */
    if (ret->val == TEST_PASSED) {
        if (boot_measurement.measurement.value.hash_buf_size != 0 ||
            boot_measurement.measurement.metadata.signer_id_size != 0) {
            ret->val = TEST_FAILED;
        }
    }
}

static void tfm_riv_test_1011(struct test_result_t *ret)
{
    struct rse_image_verification_boot_measurement_t boot_measurement = {0};
    struct riv_mcuboot_test_config config = {
        .corrupt_signature = false,
        .corrupt_public_key = false,
        .num_chains = 0,
        .bad_nv_counter = false,
        .must_be_signed = true,
        .corrupt_verification_structure = false,
        .expected_ret_val = RSE_VERIFICATION_SERVICE_SUCCESS};

    execute_mcuboot_test(ret, &config, &boot_measurement);

    /*
     * There was no chain so the measurement data should not be updated
     */
    if (ret->val == TEST_PASSED) {
        if (boot_measurement.measurement.value.hash_buf_size != 0 ||
            boot_measurement.measurement.metadata.signer_id_size != 0) {
            ret->val = TEST_FAILED;
        }
    }
}

static void tfm_riv_test_1012(struct test_result_t *ret)
{
    struct rse_image_verification_boot_measurement_t boot_measurement = {0};
    struct riv_mcuboot_test_config config = {
        .corrupt_signature = false,
        .corrupt_public_key = false,
        .num_chains = 1,
        .bad_nv_counter = false,
        .must_be_signed = true,
        .corrupt_verification_structure = true,
        .expected_ret_val = RSE_VERIFICATION_SERVICE_ERR_INVALID_ARG};

    execute_mcuboot_test(ret, &config, &boot_measurement);
}
