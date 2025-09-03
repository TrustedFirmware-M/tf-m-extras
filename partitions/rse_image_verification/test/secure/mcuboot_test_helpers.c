/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 */

#include "mcuboot_test_helpers.h"
#include "platform_nv_counters_ids.h"
#include "psa/crypto_sizes.h"
#include "psa/crypto_values.h"
#include "rse_image_verification_api.h"
#include "rse_image_verification_defs.h"
#include "signature_encoding_helper.h"
#include "stdint.h"
#include "tfm_builtin_key_ids.h"
#include <psa/crypto.h>
#include <string.h>

/*
 * This contains the MCUBoot header (0x40), the image itself (0x0b) and the
 * protected TLV (0x1c). This is MCUBoot specific, these have to be copied to
 * the destination slot.
 */
#define TEST_IMAGE_SIZE_BYTES 103

/*
 * These values are extracted manually from the test image, with the help of
 * the imgtool.py script's dumpinfo command.
 */
#define MCUBOOT_SIGN_LEN_OFFSET 240
#define MCUBOOT_SIGN_VAL_OFFSET 242
#define MCUBOOT_NV_CTR_LEN_OFFSET 81
#define MCUBOOT_NV_CTR_VAL_OFFSET 83
#define MCUBOOT_PUBKEY_TLV_SIZE_OFFSET 145
#define MCUBOOT_PUBKEY_TLV_OFFSET 147

#define VERIFICATION_DATA_BUFFER_SIZE 0x500

#define EC256_SIGNATURE_CURVE_BYTE_COUNT 32

/*
 * The PLAT_NV_COUNTER_BL2_0 counter value is 1.
 * This PLAT_NV_COUNTER ID is chosen arbitrarily for testing purposes and might
 * need to be updated if the platform changes. This counter is not set up by
 * the tests.
 * Its size is 4 bytes in every RSE platform.
 */
#define NV_COUNTER_ID_FOR_TEST PLAT_NV_COUNTER_BL2_0
#define NV_COUNTER_SIZE 4

/* The values after test_mcuboot_signed_image[3] are 0x96, 0x00, 0x00, 0x00 */
#define ARBITRARY_NV_CTR_OFFSET_IN_IMAGE 3

#define MEASUREMENT_SW_TYPE_TEST_VALUE \
    { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 }
static uint8_t measurement_sw_type[] = MEASUREMENT_SW_TYPE_TEST_VALUE;

#define MEASUREMENT_SW_VERSION_TEST_VALUE \
    { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }
static uint8_t measurement_sw_version[] = MEASUREMENT_SW_VERSION_TEST_VALUE;

/* External test image data */
extern uint8_t test_mcuboot_signed_image[];

static uint32_t
setup_single_verification_chain(struct rse_image_verification_chain_t *chain,
                                const struct riv_mcuboot_test_config *config)
{
    uint8_t reformatted_signature[PSA_SIGNATURE_MAX_SIZE] = {0};
    struct rse_image_verification_chain_link_t *link;
    uint8_t *key;

    if (config->must_be_signed) {
        chain->signing_policy = IMAGE_MUST_BE_SIGNED;
    } else {
        chain->signing_policy = IMAGE_MIGHT_BE_SIGNED;
    }

    chain->root_key_id = TFM_BUILTIN_RIV_TEST_KEY;
    chain->first_signature_size = 2 * EC256_SIGNATURE_CURVE_BYTE_COUNT;

    /*
     * The test image has an NV counter with 0x00 values.
     *
     *  Positive case:
     *     The offset_in_image points to an
     *     arbitrary location in the image that has a value
     *     larger than 1. This should cause an increment of
     *     the NV counter.
     *
     *  Negative case:
     *     The offset_in_image points to the
     *     correct location of the NV counter in the image.
     *     This should cause the NV counter verification to
     *     fail because this is smaller than the
     *     PLAT_NV_COUNTER_BL2_0 counter value.
     */
    chain->nv_counter.size =
        test_mcuboot_signed_image[MCUBOOT_NV_CTR_LEN_OFFSET];

    if (config->bad_nv_counter) {
        chain->nv_counter.offset_in_image = MCUBOOT_NV_CTR_VAL_OFFSET;
    } else {
        chain->nv_counter.offset_in_image = ARBITRARY_NV_CTR_OFFSET_IN_IMAGE;
    }

    chain->nv_counter.format = NV_COUNTER_FORMAT_LITTLE_ENDIAN;
    chain->nv_counter.id = NV_COUNTER_ID_FOR_TEST;

    parse_signature_from_rfc5480_encoding(
        &test_mcuboot_signed_image[MCUBOOT_SIGN_VAL_OFFSET],
        test_mcuboot_signed_image[MCUBOOT_SIGN_LEN_OFFSET],
        reformatted_signature, chain->first_signature_size);

    memcpy(chain->first_signature, reformatted_signature,
           chain->first_signature_size);

    if (config->corrupt_signature) {
        chain->first_signature[0] ^= 0x1;
    }

    link = chain->chain_links;
    link->type = IMAGE_VERIFICATION_KEY_TYPE_DER;
    link->alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
    link->key_family = PSA_ECC_FAMILY_SECP_R1;
    link->key_offset_in_chain_buffer = 0;
    link->chain_signature_size = 0;
    link->key_size = test_mcuboot_signed_image[MCUBOOT_PUBKEY_TLV_SIZE_OFFSET];

    key = &test_mcuboot_signed_image[MCUBOOT_PUBKEY_TLV_OFFSET];
    link->chain_data_size = link->key_size;

    memcpy(link->chain_signature_and_data + link->chain_signature_size, key,
           link->key_size);

    if (config->corrupt_public_key) {
        /*
         * Don't corrupt the first or last bytes because that is metadata
         * which isn't used
         */
        link->chain_signature_and_data[link->chain_signature_size +
                                       link->key_size - 10] ^= 0x1;
    }

    chain->chain_size = sizeof(*chain) + sizeof(*link) +
                        link->chain_signature_size + link->chain_data_size;

    return chain->chain_size;
}

static uint32_t setup_mcuboot_verification_data_common(
    uint8_t *verification_data_buffer,
    const struct riv_mcuboot_test_config *config, uint32_t num_chains)
{
    struct rse_image_verification_data_t *verification_data;
    struct rse_image_verification_chain_t *current_chain;
    uint32_t total_chains_size = 0;

    verification_data =
        (struct rse_image_verification_data_t *)verification_data_buffer;
    verification_data->chains_amount = num_chains;

    current_chain = verification_data->chains;

    for (uint32_t i = 0; i < num_chains; i++) {
        uint32_t chain_size =
            setup_single_verification_chain(current_chain, config);

        total_chains_size += chain_size;
        current_chain =
            (struct rse_image_verification_chain_t *)((uint8_t *)current_chain +
                                                      chain_size);
    }

    return sizeof(*verification_data) + total_chains_size;
}

static void setup_mcuboot_measurement_data(
    struct rse_image_verification_boot_measurement_t *boot_measurement,
    uint32_t num_chains)
{
    for (uint32_t i = 0; i < num_chains; i++) {
        boot_measurement[i].record_measurement = 1;
        boot_measurement[i].measurement_slot = i;
        boot_measurement[i].measurement.metadata.measurement_algo =
            PSA_ALG_SHA_256;
        memcpy(boot_measurement[i].measurement.metadata.sw_type,
               measurement_sw_type, sizeof(measurement_sw_type));
        boot_measurement[i].measurement.metadata.sw_type_size =
            sizeof(measurement_sw_type);

        memcpy(boot_measurement[i].measurement.metadata.version,
               measurement_sw_version, sizeof(measurement_sw_version));
        boot_measurement[i].measurement.metadata.version_size =
            sizeof(measurement_sw_version);
    }
}

void execute_mcuboot_test(
    struct test_result_t *ret, const struct riv_mcuboot_test_config *config,
    struct rse_image_verification_boot_measurement_t *boot_measurement)
{
    psa_status_t status;
    uint8_t destination_buffer[TEST_IMAGE_SIZE_BYTES] = {0};
    uint8_t verification_data_buffer[VERIFICATION_DATA_BUFFER_SIZE] = {0};
    struct rse_image_verification_data_t *verification_data;
    uint32_t boot_measurement_size;
    uint32_t verification_data_len;

    verification_data =
        (struct rse_image_verification_data_t *)verification_data_buffer;

    verification_data_len = setup_mcuboot_verification_data_common(
        verification_data_buffer, config, config->num_chains);

    setup_mcuboot_measurement_data(boot_measurement, config->num_chains);

    if (config->corrupt_verification_structure) {
        verification_data_len += 1;
    }

    status = rse_verify_and_load_image(
        test_mcuboot_signed_image, TEST_IMAGE_SIZE_BYTES, verification_data,
        verification_data_len, boot_measurement,
        sizeof(*boot_measurement) * config->num_chains, &boot_measurement_size,
        destination_buffer, TEST_IMAGE_SIZE_BYTES);

    if (config->expected_ret_val == status) {
        ret->val = TEST_PASSED;
    } else {
        ret->val = TEST_FAILED;
    }

    if (config->expected_ret_val == RSE_VERIFICATION_SERVICE_SUCCESS) {
        /* The image should be copied to the destination buffer */
        if (memcmp(destination_buffer, test_mcuboot_signed_image,
                   TEST_IMAGE_SIZE_BYTES) != 0) {
            ret->val = TEST_FAILED;
        }
    } else {
        /*
         * The image should NOT be copied to the destination buffer if
         * authentication failed
         */
        if (memcmp(destination_buffer, test_mcuboot_signed_image,
                   TEST_IMAGE_SIZE_BYTES) == 0) {
            ret->val = TEST_FAILED;
        }
    }
}
