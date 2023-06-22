/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dpe_crypto_interface.h"
#include <stdbool.h>
#include <string.h>
#include "dpe_context_mngr.h"
#include "dpe_crypto_config.h"
#include "psa/crypto.h"
#include "tfm_crypto_defs.h"

static const char attest_cdi_label[] = DPE_ATTEST_CDI_LABEL;
static const char attest_key_pair_label[] = DPE_ATTEST_KEY_PAIR_LABEL;
static const uint8_t attest_key_salt[] = DPE_ATTEST_KEY_SALT;

static psa_status_t perform_derivation(psa_key_id_t base_key,
                                       const psa_key_attributes_t *key_attr,
                                       const uint8_t *key_label,
                                       size_t key_label_len,
                                       const uint8_t *salt,
                                       size_t salt_len,
                                       psa_key_id_t *out_key_id)
{
    psa_status_t status;
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;

    assert((key_label_len != 0) && (key_label != NULL) &&
           (base_key != 0) && (key_attr != NULL) &&
           (salt_len != 0) && (salt != NULL));

    status = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
                                            salt, salt_len);
    if (status != PSA_SUCCESS) {
        goto err_abort;
    }

    status = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                          base_key);
    if (status != PSA_SUCCESS) {
        goto err_abort;
    }

    /* Supply the key label as an input to the key derivation */
    status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                           key_label, key_label_len);
    if (status != PSA_SUCCESS) {
        goto err_abort;
    }

    status = psa_key_derivation_output_key(key_attr, &op, out_key_id);
    if (status != PSA_SUCCESS) {
        goto err_abort;
    }

    /* Free resources associated with the key derivation operation */
    status = psa_key_derivation_abort(&op);
    if (status == PSA_SUCCESS) {
        goto done;
    }

    (void)psa_destroy_key(*out_key_id);

err_abort:
    (void)psa_key_derivation_abort(&op);

done:
    return status;
}

psa_status_t derive_attestation_cdi(struct layer_context_t *layer_ctx,
                                    const struct layer_context_t *parent_layer_ctx)
{
    psa_key_attributes_t derive_key_attr = PSA_KEY_ATTRIBUTES_INIT;

    /* Set key attributes for CDI key */
    psa_set_key_type(&derive_key_attr, DPE_CDI_KEY_TYPE);
    psa_set_key_algorithm(&derive_key_attr, DPE_CDI_KEY_ALG);
    psa_set_key_bits(&derive_key_attr, DPE_CDI_KEY_BITS);
    psa_set_key_usage_flags(&derive_key_attr, DPE_CDI_KEY_USAGE);

    /* Perform CDI derivation */
    /* Parent layer CDI is the base key (input secret to key derivation) */
    return perform_derivation(parent_layer_ctx->data.cdi_key_id,
                              &derive_key_attr,
                              (uint8_t *) &attest_cdi_label[0],
                              sizeof(attest_cdi_label),
                              layer_ctx->attest_cdi_hash_input,
                              sizeof(layer_ctx->attest_cdi_hash_input),
                              &layer_ctx->data.cdi_key_id);
}

psa_status_t derive_attestation_key(struct layer_context_t *layer_ctx)
{
    psa_key_attributes_t attest_key_attr = PSA_KEY_ATTRIBUTES_INIT;

    /* Set key attributes for Attest key pair derivation */
    psa_set_key_type(&attest_key_attr, DPE_ATTEST_KEY_TYPE);
    psa_set_key_algorithm(&attest_key_attr, DPE_ATTEST_KEY_ALG);
    psa_set_key_bits(&attest_key_attr, DPE_ATTEST_KEY_BITS);
    psa_set_key_usage_flags(&attest_key_attr, DPE_ATTEST_KEY_USAGE);

    /* Perform key pair derivation */
    return perform_derivation(layer_ctx->data.cdi_key_id,
                              &attest_key_attr,
                              (uint8_t *)&attest_key_pair_label[0],
                              sizeof(attest_key_pair_label),
                              attest_key_salt,
                              sizeof(attest_key_salt),
                              &layer_ctx->data.attest_key_id);
}

psa_status_t create_layer_cdi_key(struct layer_context_t *layer_ctx,
                                  const uint8_t *cdi_input,
                                  size_t cdi_input_size)
{
    psa_key_attributes_t base_attributes = PSA_KEY_ATTRIBUTES_INIT;

    /* Set key attributes for CDI key */
    psa_set_key_type(&base_attributes, DPE_CDI_KEY_TYPE);
    psa_set_key_algorithm(&base_attributes, DPE_CDI_KEY_ALG);
    psa_set_key_bits(&base_attributes, DPE_CDI_KEY_BITS);
    psa_set_key_usage_flags(&base_attributes, DPE_CDI_KEY_USAGE);

    return psa_import_key(&base_attributes,
                          cdi_input,
                          cdi_input_size,
                          &layer_ctx->data.cdi_key_id);
}

psa_status_t derive_sealing_cdi(struct layer_context_t *layer_ctx)
{
    //TODO:
    (void)layer_ctx;
    return PSA_SUCCESS;
}

psa_status_t derive_wrapping_key(struct layer_context_t *layer_ctx)
{
    //TODO:
    (void)layer_ctx;
    return PSA_SUCCESS;
}

psa_status_t create_layer_certificate(struct layer_context_t *layer_ctx)
{
    //TODO:
    (void)layer_ctx;
    return PSA_SUCCESS;
}

psa_status_t store_layer_certificate(struct layer_context_t *layer_ctx)
{
    //TODO:
    (void)layer_ctx;
    return PSA_SUCCESS;
}
