/*
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "measured_boot_api.h"
#include "psa/client.h"
#include "psa/crypto_sizes.h"
#include "psa/crypto_struct.h"
#include "psa/crypto_types.h"
#include "psa/crypto_values.h"
#include "psa/error.h"
#include "public_key_encoding_helper.h"
#include "rse_image_verification_defs.h"
#include "tfm_plat_nv_counters.h"
#include "tfm_sp_log.h"
#include <psa/crypto.h>
#include <psa/service.h>

/*
 * Calculate the hash by chunks because the whole image might not fit into the
 * PSA IOV buffers
 */
#define HASH_CHUNK_SIZE_BYTES 0x1000

/*
 * The maximum key size in bytes that can be exported from the RSE via
 * psa_export_key
 */
#define MAX_KEY_SIZE_BYTES 512

#ifndef VERIFICATION_DATA_BUFFER_SIZE
#define VERIFICATION_DATA_BUFFER_SIZE 0x400
#endif /* VERIFICATION_DATA_BUFFER_SIZE */

#ifndef CHAIN_MEASUREMENT_BUFFER_SIZE
#define CHAIN_MEASUREMENT_BUFFER_SIZE 0x200
#endif /* CHAIN_MEASUREMENT_BUFFER_SIZE */

#ifndef NV_COUNTER_MAX_SIZE_BYTES
#define NV_COUNTER_MAX_SIZE_BYTES 4
#endif /* NV_COUNTER_MAX_SIZE_BYTES */

#define RIV_INVEC_IMAGE_INDEX 0
#define RIV_INVEC_VERIFICATION_DATA_INDEX 1
#define RIV_OUTVEC_MEASUREMENT_INDEX 0
#define RIV_OUTVEC_DESTINATION_INDEX 1

struct verification_context_t {
    uint8_t *data_to_verify;
    uint32_t data_to_verify_len;
    uint8_t *signature_to_be_verified;
    uint32_t signature_len;
    uint8_t hash_to_be_verified[PSA_HASH_MAX_SIZE];
    size_t hash_length;
};

static void copy_image(uint8_t *dst, uint8_t *src, uint32_t size)
{
#ifdef RIV_DMA350_SUPPORTED
#error "DMA350 copy not implemented yet"
#else
    memcpy(dst, src, size);
#endif /* RIV_DMA350_SUPPORTED */
}

static void erase_image(uint8_t *addr, uint32_t size)
{
    memset(addr, 0, size);
}

static psa_algorithm_t get_hash_alg(psa_algorithm_t alg)
{
    if (PSA_ALG_IS_HASH(alg)) {
        return alg;
    } else {
        return PSA_ALG_SIGN_GET_HASH(alg);
    }
}

static enum rse_verification_service_err_t
compute_hash(uint8_t data[], uint32_t data_len, uint8_t hash[],
             uint32_t hash_size, size_t *hash_length, psa_algorithm_t alg)
{
    psa_hash_operation_t ctx;
    psa_status_t status;
    uint8_t *data_ptr = data;
    uint32_t remaining = data_len;

    ctx = psa_hash_operation_init();
    status = psa_hash_setup(&ctx, alg);
    if (status != PSA_SUCCESS) {
        return RSE_VERIFICATION_SERVICE_ERR_INVALID_ARG;
    }

    while (remaining > 0) {
        uint32_t chunk_size = remaining > HASH_CHUNK_SIZE_BYTES
                                  ? HASH_CHUNK_SIZE_BYTES
                                  : remaining;

        status = psa_hash_update(&ctx, data_ptr, chunk_size);
        if (status != PSA_SUCCESS) {
            psa_hash_abort(&ctx);
            return RSE_VERIFICATION_SERVICE_ERR_INTERNAL;
        }

        data_ptr += chunk_size;
        remaining -= chunk_size;
    }

    status = psa_hash_finish(&ctx, hash, hash_size, hash_length);
    if (status != PSA_SUCCESS) {
        return RSE_VERIFICATION_SERVICE_ERR_INTERNAL;
    }

    return RSE_VERIFICATION_SERVICE_SUCCESS;
}

static int32_t compare_big_endian_nv_ctr(const uint8_t *ctr_from_image,
                                  const uint8_t *ctr_from_device, uint32_t size)
{
    for (uint32_t i = 0; i < size; i++) {
        if (ctr_from_image[i] < ctr_from_device[i]) {
            return -1;
        } else if (ctr_from_image[i] > ctr_from_device[i]) {
            return 1;
        }
    }
    return 0;
}

static int32_t compare_little_endian_nv_ctr(const uint8_t *ctr_from_image,
                                     const uint8_t *ctr_from_device,
                                     uint32_t size)
{
    for (uint32_t i = 0; i < size; i++) {
        if (ctr_from_image[size - i - 1] < ctr_from_device[size - i - 1]) {
            return -1;
        } else if (ctr_from_image[size - i - 1] >
                   ctr_from_device[size - i - 1]) {
            return 1;
        }
    }
    return 0;
}

static enum rse_verification_service_err_t
verify_nv_counter(struct nv_counter_verification_info_t *nv_ctr_info,
                  uint8_t *image, uint32_t image_len)
{
    uint8_t *nv_counter_value_from_image;
    uint8_t nv_counter_value_from_device[NV_COUNTER_MAX_SIZE_BYTES];
    enum tfm_plat_err_t plat_err;

    if (nv_ctr_info->size == 0) {
        return RSE_VERIFICATION_SERVICE_SUCCESS;
    }

    if (nv_ctr_info->size > sizeof(nv_counter_value_from_device)) {
        return RSE_VERIFICATION_SERVICE_ERR_INVALID_ARG;
    }

    if ((nv_ctr_info->offset_in_image + nv_ctr_info->size) > image_len) {
        return RSE_VERIFICATION_SERVICE_ERR_INVALID_ARG;
    }

    nv_counter_value_from_image = &image[nv_ctr_info->offset_in_image];

    plat_err = tfm_plat_read_nv_counter(nv_ctr_info->id, nv_ctr_info->size,
                                        nv_counter_value_from_device);
    if (plat_err != TFM_PLAT_ERR_SUCCESS) {
        return RSE_VERIFICATION_SERVICE_ERR_NV_COUNTER;
    }

    if (nv_ctr_info->format == NV_COUNTER_FORMAT_BIG_ENDIAN) {
        if (compare_big_endian_nv_ctr(nv_counter_value_from_image,
                               nv_counter_value_from_device,
                               nv_ctr_info->size) < 0) {
            return RSE_VERIFICATION_SERVICE_ERR_NV_COUNTER;
        }
    } else if (nv_ctr_info->format == NV_COUNTER_FORMAT_LITTLE_ENDIAN) {
        if (compare_little_endian_nv_ctr(nv_counter_value_from_image,
                                  nv_counter_value_from_device,
                                  nv_ctr_info->size) < 0) {
            return RSE_VERIFICATION_SERVICE_ERR_NV_COUNTER;
        }
    } else {
        return RSE_VERIFICATION_SERVICE_ERR_INVALID_ARG;
    }

    return RSE_VERIFICATION_SERVICE_SUCCESS;
}

static enum rse_verification_service_err_t
verify_chain_link_ecdsa_raw(uint8_t *key_ptr, uint32_t key_len,
                            psa_algorithm_t alg, psa_ecc_family_t key_family,
                            uint8_t *hash_to_be_verified, uint32_t hash_length,
                            uint8_t *signature_to_be_verified,
                            uint32_t signature_len)
{
    psa_status_t status;
    psa_key_id_t key_id;
    psa_key_attributes_t key_attributes = psa_key_attributes_init();

    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&key_attributes, alg);
    psa_set_key_type(&key_attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(key_family));

    status = psa_import_key(&key_attributes, key_ptr, key_len, &key_id);
    if (status != PSA_SUCCESS) {
        return RSE_VERIFICATION_SERVICE_ERR_BAD_KEY;
    }

    status = psa_verify_hash(key_id, alg, hash_to_be_verified, hash_length,
                             signature_to_be_verified, signature_len);
    psa_destroy_key(key_id);

    if (status != PSA_SUCCESS) {
        return RSE_VERIFICATION_SERVICE_ERR_VERIFICATION_FAILED;
    }

    return RSE_VERIFICATION_SERVICE_SUCCESS;
}

static enum rse_verification_service_err_t
process_chain_link(struct rse_image_verification_chain_link_t *link,
                   uint8_t *image, uint32_t image_len,
                   struct verification_context_t *ctx)
{
    enum rse_verification_service_err_t status;
    size_t key_len = (size_t)link->key_size;
    uint8_t *key_ptr;

    if ((link->key_offset_in_chain_buffer + link->key_size) >
        (link->chain_data_size + link->chain_signature_size)) {
        return RSE_VERIFICATION_SERVICE_ERR_INVALID_ARG;
    }

    key_ptr = link->chain_signature_and_data + link->key_offset_in_chain_buffer;

    status = verify_nv_counter(&link->nv_counter, image, image_len);
    if (status != RSE_VERIFICATION_SERVICE_SUCCESS) {
        return status;
    }

    status =
        compute_hash(ctx->data_to_verify, ctx->data_to_verify_len,
                     ctx->hash_to_be_verified, sizeof(ctx->hash_to_be_verified),
                     &ctx->hash_length, get_hash_alg(link->alg));
    if (status != RSE_VERIFICATION_SERVICE_SUCCESS) {
        return status;
    }

    switch (link->type) {
    case IMAGE_VERIFICATION_KEY_TYPE_HASH:
        if (ctx->hash_length != key_len) {
            return RSE_VERIFICATION_SERVICE_ERR_VERIFICATION_FAILED;
        }
        if (memcmp(ctx->hash_to_be_verified, key_ptr, key_len) != 0) {
            status = RSE_VERIFICATION_SERVICE_ERR_VERIFICATION_FAILED;
        } else {
            status = RSE_VERIFICATION_SERVICE_SUCCESS;
        }
        break;
    case IMAGE_VERIFICATION_KEY_TYPE_RAW:
        status = verify_chain_link_ecdsa_raw(
            key_ptr, key_len, link->alg, link->key_family,
            ctx->hash_to_be_verified, ctx->hash_length,
            ctx->signature_to_be_verified, ctx->signature_len);
        break;
    case IMAGE_VERIFICATION_KEY_TYPE_DER:
        get_public_key_from_rfc5280_encoding(&key_ptr, &key_len);
        status = verify_chain_link_ecdsa_raw(
            key_ptr, key_len, link->alg, link->key_family,
            ctx->hash_to_be_verified, ctx->hash_length,
            ctx->signature_to_be_verified, ctx->signature_len);
        break;
    default:
        status = RSE_VERIFICATION_SERVICE_ERR_INVALID_ARG;
    }

    return status;
}

static enum rse_verification_service_err_t extend_measured_boot_measurement(
    uint8_t *image, uint32_t image_len,
    struct rse_image_verification_boot_measurement_t *boot_measurement)
{
    psa_status_t psa_status;
    enum rse_verification_service_err_t status;
    uint8_t image_hash[PSA_HASH_MAX_SIZE];
    size_t hash_len = 0;

    status = compute_hash(
        image, image_len, image_hash, sizeof(image_hash), &hash_len,
        boot_measurement->measurement.metadata.measurement_algo);
    if (status != RSE_VERIFICATION_SERVICE_SUCCESS) {
        return status;
    }

    psa_status = tfm_measured_boot_extend_measurement(
        boot_measurement->measurement_slot,
        boot_measurement->measurement.metadata.signer_id,
        boot_measurement->measurement.metadata.signer_id_size,
        boot_measurement->measurement.metadata.version,
        boot_measurement->measurement.metadata.version_size,
        boot_measurement->measurement.metadata.measurement_algo,
        boot_measurement->measurement.metadata.sw_type,
        boot_measurement->measurement.metadata.sw_type_size, image_hash,
        hash_len, false);

    if (psa_status != PSA_SUCCESS) {
        return RSE_VERIFICATION_SERVICE_ERR_MEASUREMENT_FAILED;
    }

    return RSE_VERIFICATION_SERVICE_SUCCESS;
}

static struct rse_image_verification_chain_link_t *
get_next_link(struct rse_image_verification_chain_link_t *current_link)
{
    return (struct rse_image_verification_chain_link_t *)&current_link
        ->chain_signature_and_data[current_link->chain_signature_size +
                                   current_link->chain_data_size];
}

static enum rse_verification_service_err_t
verify_chain_with_root_hash_lock(struct rse_image_verification_chain_t *chain,
                                 uint8_t *hash_to_be_verified,
                                 uint32_t hash_length)
{
    psa_status_t status;
    uint8_t exported_hash[PSA_HASH_MAX_SIZE];
    size_t exported_hash_length = 0;

    /* The root key must be exportable by the RIV partition */
    status = psa_export_key(chain->root_key_id, exported_hash,
                            sizeof(exported_hash), &exported_hash_length);
    if (status != PSA_SUCCESS) {
        return RSE_VERIFICATION_SERVICE_ERR_BAD_KEY;
    }

    if (exported_hash_length != hash_length) {
        return RSE_VERIFICATION_SERVICE_ERR_VERIFICATION_FAILED;
    }

    if (memcmp(exported_hash, hash_to_be_verified, hash_length) != 0) {
        return RSE_VERIFICATION_SERVICE_ERR_VERIFICATION_FAILED;
    }

    return RSE_VERIFICATION_SERVICE_SUCCESS;
}

static enum rse_verification_service_err_t verify_chain_with_root_key(
    struct rse_image_verification_chain_t *chain, psa_key_type_t root_key_type,
    psa_algorithm_t root_alg_type, uint8_t *hash_to_be_verified,
    uint32_t hash_length, uint8_t *signature_to_be_verified,
    uint32_t signature_len)
{
    enum rse_verification_service_err_t status;
    psa_status_t psa_status;

    if (PSA_KEY_TYPE_IS_UNSTRUCTURED(root_key_type)) {
        status = verify_chain_with_root_hash_lock(chain, hash_to_be_verified,
                                                  hash_length);
    } else if (PSA_KEY_TYPE_IS_ASYMMETRIC(root_key_type) ||
               PSA_KEY_TYPE_IS_PUBLIC_KEY(root_key_type)) {
        psa_status = psa_verify_hash(chain->root_key_id, root_alg_type,
                                     hash_to_be_verified, hash_length,
                                     signature_to_be_verified, signature_len);
        if (psa_status == PSA_SUCCESS) {
            status = RSE_VERIFICATION_SERVICE_SUCCESS;
        } else {
            status = RSE_VERIFICATION_SERVICE_ERR_VERIFICATION_FAILED;
        }
    } else {
        status = RSE_VERIFICATION_SERVICE_ERR_INVALID_ARG;
    }

    return status;
}

static uint32_t get_link_count(struct rse_image_verification_chain_t *chain)
{
    struct rse_image_verification_chain_link_t *current_link;
    uint32_t link_count = 0;

    current_link = chain->chain_links;

    while ((uint8_t *)current_link < ((uint8_t *)chain + chain->chain_size)) {
        link_count++;
        current_link = get_next_link(current_link);
    }

    return link_count;
}

static enum rse_verification_service_err_t store_intermediate_hash_measurement(
    struct rse_boot_verification_chain_measurement_t *chain_measurement,
    size_t boot_measurement_size, uint32_t intermediate_index, uint8_t *hash,
    size_t hash_length)
{
    uint8_t *hash_dst;

    if ((uint8_t *)chain_measurement->intermediate_hashes[intermediate_index]
            .intermediate_hash >
        ((uint8_t *)chain_measurement + boot_measurement_size)) {
        return RSE_VERIFICATION_SERVICE_ERR_INVALID_ARG;
    }

    hash_dst = chain_measurement->intermediate_hashes[intermediate_index]
                   .intermediate_hash;

    if ((hash_dst + hash_length) >
        ((uint8_t *)chain_measurement + boot_measurement_size)) {
        return RSE_VERIFICATION_SERVICE_ERR_INVALID_ARG;
    }

    memcpy(hash_dst, hash, hash_length);

    chain_measurement->intermediate_hashes[intermediate_index]
        .intermediate_hash_size = hash_length;

    return RSE_VERIFICATION_SERVICE_SUCCESS;
}

static enum rse_verification_service_err_t verify_and_store_root_hash(
    struct rse_image_verification_chain_t *chain,
    struct verification_context_t *ctx,
    struct rse_boot_verification_chain_measurement_t *chain_measurement,
    uint32_t *chain_measurement_size)
{
    enum rse_verification_service_err_t status;
    psa_key_attributes_t root_key_attributes = {0};
    psa_algorithm_t root_alg;
    psa_key_type_t root_key_type;

    /* Get the root key attributes to decide the hash algorithm */
    status = psa_get_key_attributes(chain->root_key_id, &root_key_attributes);
    if (status != PSA_SUCCESS) {
        return RSE_VERIFICATION_SERVICE_ERR_BAD_KEY;
    }

    root_alg = psa_get_key_algorithm(&root_key_attributes);
    root_key_type = psa_get_key_type(&root_key_attributes);

    status =
        compute_hash(ctx->data_to_verify, ctx->data_to_verify_len,
                     ctx->hash_to_be_verified, sizeof(ctx->hash_to_be_verified),
                     &ctx->hash_length, get_hash_alg(root_alg));
    if (status != RSE_VERIFICATION_SERVICE_SUCCESS) {
        return status;
    }

    status = verify_chain_with_root_key(
        chain, root_key_type, root_alg, ctx->hash_to_be_verified,
        ctx->hash_length, ctx->signature_to_be_verified, ctx->signature_len);

    if (status != RSE_VERIFICATION_SERVICE_SUCCESS) {
        return status;
    }

    if (chain_measurement->root_hash + ctx->hash_length >
        ((uint8_t *)chain_measurement + *chain_measurement_size)) {
        /* Make sure the measurement fits in the buffer */
        return RSE_VERIFICATION_SERVICE_ERR_INVALID_ARG;
    }

    memcpy(chain_measurement->root_hash, ctx->hash_to_be_verified,
           ctx->hash_length);
    chain_measurement->root_hash_size = ctx->hash_length;
    *chain_measurement_size =
        sizeof(*chain_measurement) +
        chain_measurement->intermediate_hashes_amount *
            sizeof(*chain_measurement->intermediate_hashes);

    return status;
}

static enum rse_verification_service_err_t process_chain(
    struct rse_image_verification_chain_t *chain, uint8_t *image,
    uint32_t image_len,
    struct rse_boot_verification_chain_measurement_t *chain_measurement,
    uint32_t *chain_measurement_size)
{
    enum rse_verification_service_err_t status;
    struct verification_context_t ctx;

    struct rse_image_verification_chain_link_t *current_link;
    uint32_t link_count;

    chain_measurement->intermediate_hashes_amount = 0;

    status = verify_nv_counter(&chain->nv_counter, image, image_len);
    if (status != RSE_VERIFICATION_SERVICE_SUCCESS) {
        return status;
    }

    /* The image hash is the first thing to be verified in a chain */
    ctx.data_to_verify = image;
    ctx.data_to_verify_len = image_len;
    ctx.signature_to_be_verified = chain->first_signature;
    ctx.signature_len = chain->first_signature_size;
    if (ctx.signature_len > RIV_FIRST_SIGNATURE_MAX_SIZE_BYTES) {
        return RSE_VERIFICATION_SERVICE_ERR_INVALID_ARG;
    }

    link_count = get_link_count(chain);
    current_link = chain->chain_links;
    for (uint32_t link_index = 0; link_index < link_count; link_index++) {
        /*
         * Make sure the current link is valid and doesn't index out of the
         * verification buffer
         */
        if (((uint8_t *)current_link->chain_signature_and_data +
             current_link->chain_signature_size +
             current_link->chain_data_size) >
            (uint8_t *)chain + chain->chain_size) {
            return RSE_VERIFICATION_SERVICE_ERR_INVALID_ARG;
        }

        status = process_chain_link(current_link, image, image_len, &ctx);
        if (status != RSE_VERIFICATION_SERVICE_SUCCESS) {
            return status;
        }

        if (link_index != 0) {
            /*
            * The first link doesn't have to be stored in the intermediate
            * hash array because it contains the hash of the image
            */
            status = store_intermediate_hash_measurement(
                chain_measurement, *chain_measurement_size,
                chain_measurement->intermediate_hashes_amount,
                ctx.hash_to_be_verified, ctx.hash_length);
            if (status != RSE_VERIFICATION_SERVICE_SUCCESS) {
                return status;
            }

            chain_measurement->intermediate_hashes_amount++;
        }

        /* Setup the data for the next verification */
        ctx.data_to_verify =
            &current_link
                 ->chain_signature_and_data[current_link->chain_signature_size];
        ctx.data_to_verify_len = current_link->chain_data_size;

        ctx.signature_to_be_verified = current_link->chain_signature_and_data;
        ctx.signature_len = current_link->chain_signature_size;

        current_link = get_next_link(current_link);
    }

    status = verify_and_store_root_hash(chain, &ctx, chain_measurement,
                                        chain_measurement_size);

    return status;
}

static enum rse_verification_service_err_t is_verification_data_size_correct(
    struct rse_image_verification_data_t *verification_data,
    uint32_t verification_data_len)
{
    uint32_t calculated_size = sizeof(struct rse_image_verification_data_t);
    struct rse_image_verification_chain_t *current_chain;

    if (verification_data == NULL) {
        return RSE_VERIFICATION_SERVICE_ERR_INVALID_ARG;
    }

    if (verification_data_len < calculated_size) {
        return RSE_VERIFICATION_SERVICE_ERR_INVALID_ARG;
    }

    current_chain = verification_data->chains;

    for (uint32_t i = 0; i < verification_data->chains_amount; i++) {
        if ((uint8_t *)current_chain >=
            ((uint8_t *)verification_data + verification_data_len)) {
            return RSE_VERIFICATION_SERVICE_ERR_INVALID_ARG;
        }

        calculated_size += current_chain->chain_size;
        current_chain =
            (struct rse_image_verification_chain_t
                 *)((uint8_t *)current_chain + current_chain->chain_size);
    }

    if (calculated_size != verification_data_len) {
        return RSE_VERIFICATION_SERVICE_ERR_INVALID_ARG;
    }

    return RSE_VERIFICATION_SERVICE_SUCCESS;
}

static enum rse_verification_service_err_t
set_boot_measurement_metadata(struct rse_boot_measurement_metadata_t *metadata,
                              struct rse_image_verification_chain_t *chain)
{
    enum rse_verification_service_err_t status;
    psa_status_t psa_status;
    psa_key_attributes_t key_attributes = psa_key_attributes_init();
    psa_key_type_t root_key_type;
    uint8_t exported_key[MAX_KEY_SIZE_BYTES];
    uint32_t key_size;
    struct rse_image_verification_chain_link_t *current_link;
    uint32_t additional_signer_amount = 0;
    uint8_t *key_ptr;
    uint32_t link_count;

    psa_status = psa_get_key_attributes(chain->root_key_id, &key_attributes);
    if (psa_status != PSA_SUCCESS) {
        return RSE_VERIFICATION_SERVICE_ERR_BAD_KEY;
    }

    root_key_type = psa_get_key_type(&key_attributes);
    if (PSA_KEY_TYPE_IS_UNSTRUCTURED(root_key_type)) {
        psa_status = psa_export_key(chain->root_key_id, metadata->signer_id,
                                    sizeof(metadata->signer_id),
                                    &metadata->signer_id_size);
        if (psa_status != PSA_SUCCESS) {
            return RSE_VERIFICATION_SERVICE_ERR_BAD_KEY;
        }
    } else {
        psa_status = psa_export_key(chain->root_key_id, exported_key,
                                    sizeof(exported_key), (size_t *)&key_size);
        if (psa_status != PSA_SUCCESS) {
            return RSE_VERIFICATION_SERVICE_ERR_BAD_KEY;
        }
        status =
            compute_hash(exported_key, key_size, metadata->signer_id,
                         sizeof(metadata->signer_id), &metadata->signer_id_size,
                         metadata->measurement_algo);
        if (status != RSE_VERIFICATION_SERVICE_SUCCESS) {
            return status;
        }
    }

    link_count = get_link_count(chain);
    current_link = chain->chain_links;

    for (uint32_t link_index = 0; link_index < link_count; link_index++) {
        if ((current_link->type == IMAGE_VERIFICATION_KEY_TYPE_RAW) ||
            (current_link->type == IMAGE_VERIFICATION_KEY_TYPE_DER)) {

            if (additional_signer_amount >= ADDITIONAL_SIGNER_MAX_AMOUNT) {
                return RSE_VERIFICATION_SERVICE_ERR_INVALID_ARG;
            }

            if ((link_index == (link_count - 1)) &&
                (PSA_KEY_TYPE_IS_UNSTRUCTURED(root_key_type))) {
                /*
                 * If the root_key is an unstructured key then the last link's
                 * hash is the root key in OTP. This means this link's hash
                 * doesn't need to be saved because it is already stored in the
                 * metadata->signer_id.
                 */
                break;
            }
            key_ptr = &current_link->chain_signature_and_data
                           [current_link->key_offset_in_chain_buffer];
            status = compute_hash(
                key_ptr, current_link->key_size,
                metadata->additional_signers[additional_signer_amount]
                    .signer_id,
                sizeof(metadata->additional_signers[additional_signer_amount]
                           .signer_id),
                &metadata->additional_signers[additional_signer_amount]
                     .signer_id_size,
                metadata->measurement_algo);
            if (status != RSE_VERIFICATION_SERVICE_SUCCESS) {
                return status;
            }

            additional_signer_amount++;
        }

        current_link = get_next_link(current_link);
    }

    metadata->additional_signer_amount = additional_signer_amount;

    return RSE_VERIFICATION_SERVICE_SUCCESS;
}

static enum rse_verification_service_err_t
set_boot_measurement_value(struct rse_boot_measurement_value_t *value,
                           uint8_t *measurement_buffer,
                           uint32_t measurement_size)
{
    enum rse_verification_service_err_t status;

    status =
        compute_hash(measurement_buffer, measurement_size, value->hash_buf,
                     sizeof(value->hash_buf), (size_t *)&value->hash_buf_size,
                     MEASURED_BOOT_HASH_ALG);

    return status;
}

static enum rse_verification_service_err_t populate_boot_measurement(
    struct rse_image_verification_boot_measurement_t *boot_measurement,
    struct rse_image_verification_chain_t *current_chain,
    uint8_t *chain_measurement_buffer, uint32_t current_chain_measurement_size,
    uint8_t *image, uint32_t image_len)
{
    enum rse_verification_service_err_t status;

    status = set_boot_measurement_metadata(
        &boot_measurement->measurement.metadata, current_chain);
    if (status != RSE_VERIFICATION_SERVICE_SUCCESS) {
        return status;
    }

    status = set_boot_measurement_value(&boot_measurement->measurement.value,
                                        chain_measurement_buffer,
                                        current_chain_measurement_size);
    if (status != RSE_VERIFICATION_SERVICE_SUCCESS) {
        return status;
    }

    if (boot_measurement->record_measurement == 1) {
        status = extend_measured_boot_measurement(image, image_len,
                                                  boot_measurement);
        if (status != RSE_VERIFICATION_SERVICE_SUCCESS) {
            return status;
        }
    }

    return RSE_VERIFICATION_SERVICE_SUCCESS;
}

static enum rse_verification_service_err_t authenticate_and_measure_image(
    uint8_t *image, uint32_t image_len,
    struct rse_image_verification_data_t *verification_data,
    struct rse_image_verification_boot_measurement_t *boot_measurement,
    uint32_t boot_measurement_len)
{
    enum rse_verification_service_err_t status;
    struct rse_image_verification_chain_t *current_chain;
    uint8_t current_chain_measurement_buffer[CHAIN_MEASUREMENT_BUFFER_SIZE];
    uint32_t current_chain_measurement_size;

    if (verification_data->chains_amount == 0) {
        /* No chain present, nothing to use for verification, return success */
        return RSE_VERIFICATION_SERVICE_SUCCESS;
    }

    if (boot_measurement == NULL) {
        /*
         * If the verification_data->chains_amount is not 0 then the
         * boot_measurement cannot be NULL
         */
        return RSE_VERIFICATION_SERVICE_ERR_INVALID_ARG;
    }

    if (boot_measurement_len <
        (verification_data->chains_amount *
         sizeof(struct rse_image_verification_boot_measurement_t))) {
        /*
         * The boot_measurement is not large enough to hold measurements
         * for each chain
         */
        return RSE_VERIFICATION_SERVICE_ERR_INVALID_ARG;
    }

    current_chain = &verification_data->chains[0];
    /* Traverse through the chains and verify each of them */
    for (uint32_t i = 0; i < verification_data->chains_amount; i++) {
        current_chain_measurement_size =
            sizeof(current_chain_measurement_buffer);

        status =
            process_chain(current_chain, image, image_len,
                          (struct rse_boot_verification_chain_measurement_t *)
                              current_chain_measurement_buffer,
                          &current_chain_measurement_size);

        if (status == RSE_VERIFICATION_SERVICE_SUCCESS) {
            /*
             * The measurement is only populated if the verification was
             * successful
             */
            status = populate_boot_measurement(
                &boot_measurement[i], current_chain,
                current_chain_measurement_buffer,
                current_chain_measurement_size, image, image_len);
            if (status != RSE_VERIFICATION_SERVICE_SUCCESS) {
                return status;
            }

        } else {
            /*
             * If a MUST_BE_SIGNED chain fails, then don't check the
             * rest of the chains and return the error.
             * If the chain is MIGHT_BE_SIGNED, continue to the next chain.
             */
            if (current_chain->signing_policy == IMAGE_MUST_BE_SIGNED) {
                return status;
            }
        }

        current_chain =
            (struct rse_image_verification_chain_t
                 *)((uint8_t *)current_chain + current_chain->chain_size);
    }

    /* Every MUST_BE_SIGNED chain was verified successfully */
    return RSE_VERIFICATION_SERVICE_SUCCESS;
}

static enum rse_verification_service_err_t extract_iovec_values(
    const psa_msg_t *msg, uint8_t **image, uint32_t *image_len,
    uint8_t *verification_data_buffer, uint32_t *verification_data_len,
    struct rse_image_verification_boot_measurement_t **boot_measurement,
    uint32_t *boot_measurement_len, uint8_t **destination,
    uint32_t *destination_len)
{
    uint32_t bytes_read;

    *image = (uint8_t *)psa_map_invec(msg->handle, RIV_INVEC_IMAGE_INDEX);
    if (*image == NULL) {
        return RSE_VERIFICATION_SERVICE_ERR_INVALID_ARG;
    }
    *image_len = msg->in_size[RIV_INVEC_IMAGE_INDEX];

    if (msg->in_size[RIV_INVEC_VERIFICATION_DATA_INDEX] >
        VERIFICATION_DATA_BUFFER_SIZE) {
        return (enum rse_verification_service_err_t)PSA_ERROR_PROGRAMMER_ERROR;
    }
    bytes_read = psa_read(msg->handle, RIV_INVEC_VERIFICATION_DATA_INDEX,
                          verification_data_buffer,
                          msg->in_size[RIV_INVEC_VERIFICATION_DATA_INDEX]);
    if (bytes_read != msg->in_size[RIV_INVEC_VERIFICATION_DATA_INDEX]) {
        return (enum rse_verification_service_err_t)PSA_ERROR_PROGRAMMER_ERROR;
    }
    *verification_data_len = bytes_read;

    /* boot_measurement can be NULL if chain_amount is 0 (no chain to verify) */
    if (msg->out_size[RIV_OUTVEC_MEASUREMENT_INDEX] > 0) {
        *boot_measurement =
            (struct rse_image_verification_boot_measurement_t *)psa_map_outvec(
                msg->handle, RIV_OUTVEC_MEASUREMENT_INDEX);
        if (*boot_measurement == NULL) {
            return (enum rse_verification_service_err_t)
                PSA_ERROR_PROGRAMMER_ERROR;
        }
    }
    *boot_measurement_len = msg->out_size[RIV_OUTVEC_MEASUREMENT_INDEX];

    *destination =
        (uint8_t *)psa_map_outvec(msg->handle, RIV_OUTVEC_DESTINATION_INDEX);
    if (*destination == NULL) {
        return (enum rse_verification_service_err_t)PSA_ERROR_PROGRAMMER_ERROR;
    }
    *destination_len = msg->out_size[RIV_OUTVEC_DESTINATION_INDEX];

    return RSE_VERIFICATION_SERVICE_SUCCESS;
}

static psa_status_t rse_verify_and_load_image_handler(const psa_msg_t *msg)
{
    uint8_t *image;
    uint32_t image_len;
    uint8_t *destination;
    uint32_t destination_len;
    uint8_t verification_data_buffer[VERIFICATION_DATA_BUFFER_SIZE];
    uint32_t verification_data_size;
    struct rse_image_verification_boot_measurement_t *boot_measurement = NULL;
    uint32_t boot_measurement_len = 0;
    psa_status_t status;

    status = extract_iovec_values(
        msg, &image, &image_len, verification_data_buffer,
        &verification_data_size, &boot_measurement, &boot_measurement_len,
        &destination, &destination_len);
    if (status != RSE_VERIFICATION_SERVICE_SUCCESS) {
        goto cleanup;
    }

    status = is_verification_data_size_correct(
        (struct rse_image_verification_data_t *)verification_data_buffer,
        verification_data_size);
    if (status != RSE_VERIFICATION_SERVICE_SUCCESS) {
        goto cleanup;
    }

    /*
     * If the image was already copied to the destination by the caller then
     * this can be skipped
     */
    if (image != destination) {
        copy_image(destination, image, image_len);
    }

    status = authenticate_and_measure_image(
        destination, image_len,
        (struct rse_image_verification_data_t *)verification_data_buffer,
        boot_measurement, boot_measurement_len);

    if (status != RSE_VERIFICATION_SERVICE_SUCCESS) {
        erase_image(destination, image_len);
    }

cleanup:
    if (image != NULL) {
        psa_unmap_invec(msg->handle, RIV_INVEC_IMAGE_INDEX);
    }
    if (boot_measurement != NULL) {
        psa_unmap_outvec(msg->handle, RIV_OUTVEC_MEASUREMENT_INDEX,
                         boot_measurement_len);
    }
    if (destination != NULL) {
        psa_unmap_outvec(msg->handle, RIV_OUTVEC_DESTINATION_INDEX,
                         destination_len);
    }

    return status;
}

psa_status_t tfm_rse_image_verification_service_sfn(const psa_msg_t *msg)
{
    switch (msg->type) {
    case RSE_IMAGE_VERIFICATION_LOAD_IMAGE:
        return rse_verify_and_load_image_handler(msg);
    default:
        /* Invalid message type */
        return PSA_ERROR_NOT_SUPPORTED;
    }
}

/**
 * \brief The rse image verification partition's entry function.
 */
psa_status_t tfm_rse_image_verification_init(void)
{
    LOG_INFFMT("RSE Image Verification Partition initialized\r\n");

    return PSA_SUCCESS;
}
