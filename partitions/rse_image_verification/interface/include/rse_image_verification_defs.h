/*
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __RSE_IMAGE_VERIFICATION_DEFS_H__
#define __RSE_IMAGE_VERIFICATION_DEFS_H__

#include <stdbool.h>
#include <stdint.h>
#include "cmsis_compiler.h"
#include "psa/client.h"
#include "psa/crypto.h"
#include "rse_boot_measurement.h"


#define RSE_IMAGE_VERIFICATION_LOAD_IMAGE 1001U

#ifndef RIV_FIRST_SIGNATURE_MAX_SIZE_BYTES
#define RIV_FIRST_SIGNATURE_MAX_SIZE_BYTES 0x60
#endif /* RIV_FIRST_SIGNATURE_MAX_SIZE_BYTES */

#ifdef __cplusplus
extern "C" {
#endif

enum nv_counter_format_t {
    NV_COUNTER_FORMAT_LITTLE_ENDIAN,
    NV_COUNTER_FORMAT_BIG_ENDIAN,
};

enum image_verification_signing_policy_t {
    IMAGE_MUST_BE_SIGNED = 0xA5A58181,
    IMAGE_MIGHT_BE_SIGNED = 0x18185A5A,
};

enum image_verification_key_type_t {
    IMAGE_VERIFICATION_KEY_TYPE_HASH,
    IMAGE_VERIFICATION_KEY_TYPE_RAW,
    IMAGE_VERIFICATION_KEY_TYPE_DER,
};

/* This is not used yet */
enum image_verification_data_format_t {
    IMAGE_VERIFICATION_DATA_FORMAT_RAW,
    IMAGE_VERIFICATION_DATA_FORMAT_COSE,
};

enum rse_verification_service_err_t {
    RSE_VERIFICATION_SERVICE_SUCCESS = 0,
    RSE_VERIFICATION_SERVICE_ERR_INVALID_ARG = -1,
    RSE_VERIFICATION_SERVICE_ERR_VERIFICATION_FAILED = -2,
    RSE_VERIFICATION_SERVICE_ERR_BAD_KEY = -3,
    RSE_VERIFICATION_SERVICE_ERR_NV_COUNTER = -4,
    RSE_VERIFICATION_SERVICE_ERR_INTERNAL = -5,
    RSE_VERIFICATION_SERVICE_ERR_MEASUREMENT_FAILED = -6,
    RSE_VERIFICATION_SERVICE_ERR_NOT_SUPPORTED = -7,

    _RSE_VERIFICATION_SERVICE_ERR_PAD = UINT32_MAX
};

__PACKED_STRUCT nv_counter_verification_info_t {
    uint32_t offset_in_image;
    uint32_t size;
    enum nv_counter_format_t format;
    uint32_t id;
};

__PACKED_STRUCT rse_image_verification_chain_link_t {
    psa_algorithm_t alg;
    psa_ecc_family_t key_family;
    enum image_verification_key_type_t type;
    struct nv_counter_verification_info_t nv_counter;
    uint32_t key_offset_in_chain_buffer;
    uint32_t key_size;
    uint32_t chain_signature_size;
    uint32_t chain_data_size;
    uint8_t chain_signature_and_data[];
};

__PACKED_STRUCT rse_boot_verification_chain_measurement_t {
    uint8_t root_hash[PSA_HASH_MAX_SIZE];
    uint32_t root_hash_size;
    uint32_t intermediate_hashes_amount;
    struct {
        uint32_t intermediate_hash_size;
        uint8_t intermediate_hash[PSA_HASH_MAX_SIZE];
    } intermediate_hashes[];
};

__PACKED_STRUCT rse_image_verification_chain_t {
    uint32_t chain_size;
    enum image_verification_signing_policy_t signing_policy;
    struct nv_counter_verification_info_t nv_counter;
    psa_key_id_t root_key_id;

    uint32_t first_signature_size;
    uint8_t first_signature[RIV_FIRST_SIGNATURE_MAX_SIZE_BYTES];

    struct rse_image_verification_chain_link_t chain_links[];
};

__PACKED_STRUCT rse_image_verification_data_t {
    uint32_t chains_amount;
    struct rse_image_verification_chain_t chains[];
};

struct rse_image_verification_boot_measurement_t {
    uint8_t record_measurement;
    uint32_t measurement_slot;
    struct rse_boot_measurement_t measurement;
};

#ifdef __cplusplus
}
#endif

#endif /* __RSE_IMAGE_VERIFICATION_DEFS_H__ */
