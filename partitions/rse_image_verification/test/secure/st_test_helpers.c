/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 */

#include "st_test_helpers.h"
#include "rse_image_verification_api.h"
#include "stdint.h"
#include "tfm_builtin_key_ids.h"
#include <psa/crypto.h>
#include <string.h>

#define MAX_TEST_CHAIN_COUNT 2
#define VERIFICATION_DATA_BUFFER_SIZE 0x500

/*
 * These values are extracted manually from the test image
 */
#define ST_SIGN_LEN_OFFSET 12
#define ST_SIGN_VAL_OFFSET 404
#define ST_PUBKEY_TLV_SIZE_OFFSET 304
#define ST_PUBKEY_TLV_OFFSET 308
#define ST_TLV_AND_HEADER_SIZE 404
#define ST_ELF_SEG0_OFFSET_AFTER_SIGNATURE 140
#define ST_SEG0_OFFSET_IN_IMAGE 628
#define ST_SEG0_SIZE 32
#define ST_SEG_HASH_SIZE 32

#define MEASUREMENT_SW_TYPE_TEST_VALUE \
    { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 }
static uint8_t measurement_sw_type[] = MEASUREMENT_SW_TYPE_TEST_VALUE;

#define MEASUREMENT_SW_VERSION_TEST_VALUE \
    { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }
static uint8_t measurement_sw_version[] = MEASUREMENT_SW_VERSION_TEST_VALUE;

/* External test image data */
extern uint8_t test_st_signed_image[];

static uint32_t
setup_single_st_verification_chain(struct rse_image_verification_chain_t *chain,
                                   const struct riv_st_test_config *config)
{
    struct rse_image_verification_chain_link_t *link_0;
    struct rse_image_verification_chain_link_t *link_1;

    chain->signing_policy = IMAGE_MUST_BE_SIGNED;
    chain->first_signature_size = 0;
    chain->nv_counter.size = 0;
    chain->root_key_id = TFM_BUILTIN_RIV_TEST_KEY;

    link_0 = chain->chain_links;
    link_0->type = IMAGE_VERIFICATION_KEY_TYPE_HASH;
    link_0->alg = PSA_ALG_SHA_256;
    link_0->key_family = PSA_ECC_FAMILY_SECP_R1;

    /* Parse signature length from header */
    link_0->chain_signature_size = test_st_signed_image[ST_SIGN_LEN_OFFSET];
    memcpy(link_0->chain_signature_and_data,
           &test_st_signed_image[ST_SIGN_VAL_OFFSET],
           link_0->chain_signature_size);

    if (config->corrupt_signature) {
        link_0->chain_signature_and_data[0] ^= 0x1;
    }

    link_0->chain_data_size = ST_TLV_AND_HEADER_SIZE;
    memcpy(&link_0->chain_signature_and_data[link_0->chain_signature_size],
           test_st_signed_image, link_0->chain_data_size);

    if (config->corrupt_image_hash) {
        link_0->chain_signature_and_data[link_0->chain_signature_size] ^= 0x1;
    }

    /* Hash size for the segment */
    link_0->key_size = ST_SEG_HASH_SIZE;
    link_0->key_offset_in_chain_buffer =
        link_0->chain_signature_size + ST_ELF_SEG0_OFFSET_AFTER_SIGNATURE;
    link_0->nv_counter.size = 0;

    /* Setup second link */
    link_1 = (struct rse_image_verification_chain_link_t *)
                ((uint8_t *)link_0->chain_signature_and_data +
                link_0->chain_signature_size + link_0->chain_data_size);
    link_1->type = IMAGE_VERIFICATION_KEY_TYPE_DER;
    link_1->alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
    link_1->key_family = PSA_ECC_FAMILY_SECP_R1;
    link_1->chain_signature_size = 0;
    link_1->key_offset_in_chain_buffer = 0;

    /* Parse public key size from pubkey info TLV */
    link_1->key_size = test_st_signed_image[ST_PUBKEY_TLV_SIZE_OFFSET];
    memcpy(link_1->chain_signature_and_data + link_1->chain_signature_size,
           &test_st_signed_image[ST_PUBKEY_TLV_OFFSET], link_1->key_size);

    if (config->corrupt_public_key) {
        link_1->chain_signature_and_data[link_1->chain_signature_size] ^= 0x1;
    }

    link_1->chain_data_size = link_1->key_size;
    link_1->nv_counter.size = 0;

    /* Calculate total chain size */
    chain->chain_size = sizeof(*chain) + sizeof(*link_0) +
                        link_0->chain_signature_size + link_0->chain_data_size +
                        sizeof(*link_1) + link_1->chain_signature_size +
                        link_1->chain_data_size;

    return chain->chain_size;
}

static uint32_t
setup_st_verification_data_common(uint8_t *verification_data_buffer,
                                  const struct riv_st_test_config *config,
                                  uint32_t num_chains)
{
    struct rse_image_verification_data_t *verification_data;
    struct rse_image_verification_chain_t *current_chain;
    uint32_t total_chains_size = 0;

    verification_data =
        (struct rse_image_verification_data_t *)verification_data_buffer;
    verification_data->chains_amount = num_chains;

    current_chain = verification_data->chains;

    /* Setup all requested chains */
    for (uint32_t i = 0; i < num_chains; i++) {
        uint32_t chain_size =
            setup_single_st_verification_chain(current_chain, config);

        total_chains_size += chain_size;
        current_chain =
            (struct rse_image_verification_chain_t *)((uint8_t *)current_chain +
                                                      chain_size);
    }

    return sizeof(*verification_data) + total_chains_size;
}

static void setup_st_measurement_data(
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

void execute_st_test(struct test_result_t *ret,
                     const struct riv_st_test_config *config,
                     struct rse_image_verification_boot_measurement_t *boot_measurement)
{
    psa_status_t status;
    uint8_t destination_buffer[ST_SEG0_SIZE] = {0};
    uint8_t verification_data_buffer[VERIFICATION_DATA_BUFFER_SIZE] = {0};
    uint32_t boot_measurement_size;
    uint32_t verification_data_len;

    /* Setup verification data based on test configuration */
    verification_data_len = setup_st_verification_data_common(
        verification_data_buffer, config, config->num_chains);

    setup_st_measurement_data(boot_measurement, config->num_chains);

    /* Execute the test */
    status = rse_verify_and_load_image(
        &test_st_signed_image[ST_SEG0_OFFSET_IN_IMAGE], ST_SEG0_SIZE,
        (struct rse_image_verification_data_t *)verification_data_buffer,
        verification_data_len, boot_measurement, sizeof(*boot_measurement) * config->num_chains, &boot_measurement_size,
        destination_buffer, ST_SEG0_SIZE);

    if (config->expected_ret_val == status) {
        ret->val = TEST_PASSED;
    } else {
        ret->val = TEST_FAILED;
        /* Don't check the destination buffer, the test failed anyway */
        return;
    }

    if (config->expected_ret_val == RSE_VERIFICATION_SERVICE_SUCCESS) {
        /* The image should be copied to the destination buffer */
        if (memcmp(destination_buffer,
                   &test_st_signed_image[ST_SEG0_OFFSET_IN_IMAGE],
                   ST_SEG0_SIZE) != 0) {
            ret->val = TEST_FAILED;
        }
    } else {
        /* The image should NOT be copied to the destination buffer */
        if (memcmp(destination_buffer,
                   &test_st_signed_image[ST_SEG0_OFFSET_IN_IMAGE],
                   ST_SEG0_SIZE) == 0) {
            ret->val = TEST_FAILED;
        }
    }
}
