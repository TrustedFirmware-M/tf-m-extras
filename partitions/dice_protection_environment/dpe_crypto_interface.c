/*
 * Copyright (c) 2023-2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dpe_crypto_interface.h"
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include "dpe_context_mngr.h"
#include "dpe_crypto_config.h"
#include "psa/crypto.h"
#include "dpe_plat.h"

static const char attest_cdi_label[] = DPE_ATTEST_CDI_LABEL;
static const char exported_attest_cdi_label[] = DPE_ATTEST_EXPORTED_CDI_LABEL;
static const char seal_cdi_label[] = DPE_SEAL_CDI_LABEL;
static const char exported_seal_cdi_label[] = DPE_SEAL_EXPORTED_CDI_LABEL;
static const char default_attest_key_deriv_label[] = DPE_ATTEST_KEY_PAIR_LABEL;
static const char id_label[] = DPE_ID_LABEL;
static const uint8_t attest_key_salt[] = DPE_ATTEST_KEY_SALT;
static const uint8_t id_salt[] = DPE_ID_SALT;

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

    if (*out_key_id != PSA_KEY_ID_NULL) {
        /* Remove any previously derived keys */
        (void)psa_destroy_key(*out_key_id);
    }

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

psa_status_t derive_attestation_cdi(struct cert_context_t *cert_ctx,
                                    const struct cert_context_t *parent_cert_ctx)
{
    psa_key_attributes_t derive_key_attr = PSA_KEY_ATTRIBUTES_INIT;

    /* Set key attributes for CDI key */
    psa_set_key_type(&derive_key_attr, DPE_CDI_KEY_TYPE);
    psa_set_key_algorithm(&derive_key_attr, DPE_CDI_KEY_ALG);
    psa_set_key_bits(&derive_key_attr, DPE_CDI_KEY_BITS);
    psa_set_key_usage_flags(&derive_key_attr, DPE_CDI_KEY_USAGE);

    /* Perform CDI derivation */
    /* Parent certificate's CDI is the base key (input secret to key derivation) */

    if (cert_ctx->is_cdi_to_be_exported) {
        return perform_derivation(parent_cert_ctx->data.attest_cdi_key_id,
                                  &derive_key_attr,
                                  (uint8_t *) &exported_attest_cdi_label[0],
                                  sizeof(exported_attest_cdi_label),
                                  cert_ctx->attest_cdi_hash_input,
                                  sizeof(cert_ctx->attest_cdi_hash_input),
                                  &cert_ctx->data.attest_cdi_key_id);

    } else {
        return perform_derivation(parent_cert_ctx->data.attest_cdi_key_id,
                                  &derive_key_attr,
                                  (uint8_t *) &attest_cdi_label[0],
                                  sizeof(attest_cdi_label),
                                  cert_ctx->attest_cdi_hash_input,
                                  sizeof(cert_ctx->attest_cdi_hash_input),
                                  &cert_ctx->data.attest_cdi_key_id);
    }
}

psa_status_t derive_attestation_key(struct cert_context_t *cert_ctx)
{
    psa_status_t status;
    psa_key_attributes_t attest_key_attr = PSA_KEY_ATTRIBUTES_INIT;

    /* Set key attributes for Attest key pair derivation */
    psa_set_key_type(&attest_key_attr, DPE_ATTEST_KEY_TYPE);
    psa_set_key_algorithm(&attest_key_attr, DPE_ATTEST_KEY_ALG);
    psa_set_key_bits(&attest_key_attr, DPE_ATTEST_KEY_BITS);
    psa_set_key_usage_flags(&attest_key_attr, DPE_ATTEST_KEY_USAGE);

    /* Perform key pair derivation */

    if (cert_ctx->data.external_key_deriv_label_len > 0) {
        /* Use the external label provided for key derivation */
        status = perform_derivation(cert_ctx->data.attest_cdi_key_id,
                    &attest_key_attr,
                    &cert_ctx->data.external_key_deriv_label[0],  /* External label */
                    cert_ctx->data.external_key_deriv_label_len,
                    attest_key_salt,
                    sizeof(attest_key_salt),
                    &cert_ctx->data.attest_key_id);
    } else {
        /* Use the default label for key derivation */
        status = perform_derivation(cert_ctx->data.attest_cdi_key_id,
                    &attest_key_attr,
                    (uint8_t *)&default_attest_key_deriv_label[0], /* Default label */
                    sizeof(default_attest_key_deriv_label),
                    attest_key_salt,
                    sizeof(attest_key_salt),
                    &cert_ctx->data.attest_key_id);
    }

    if (status != PSA_SUCCESS) {
        return status;
    }

    return psa_export_public_key(cert_ctx->data.attest_key_id,
                                 &cert_ctx->data.attest_pub_key[0],
                                 sizeof(cert_ctx->data.attest_pub_key),
                                 &cert_ctx->data.attest_pub_key_len);
}

psa_status_t derive_seal_cdi(struct cert_context_t *cert_ctx,
                             const struct cert_context_t *parent_cert_ctx)
{
    psa_key_attributes_t derive_key_attr = PSA_KEY_ATTRIBUTES_INIT;

    /* Set key attributes for CDI key */
    psa_set_key_type(&derive_key_attr, DPE_CDI_KEY_TYPE);
    psa_set_key_algorithm(&derive_key_attr, DPE_CDI_KEY_ALG);
    psa_set_key_bits(&derive_key_attr, DPE_CDI_KEY_BITS);
    psa_set_key_usage_flags(&derive_key_attr, DPE_CDI_KEY_USAGE);

    /* Perform CDI derivation */
    /* Parent certificate's CDI is the base key (input secret to key derivation) */

    if (cert_ctx->is_cdi_to_be_exported) {
        return perform_derivation(parent_cert_ctx->data.seal_cdi_key_id,
                                  &derive_key_attr,
                                  (uint8_t *) &exported_seal_cdi_label[0],
                                  sizeof(exported_seal_cdi_label),
                                  cert_ctx->seal_cdi_hash_input,
                                  sizeof(cert_ctx->seal_cdi_hash_input),
                                  &cert_ctx->data.seal_cdi_key_id);

    } else {
        return perform_derivation(parent_cert_ctx->data.seal_cdi_key_id,
                                  &derive_key_attr,
                                  (uint8_t *) &seal_cdi_label[0],
                                  sizeof(seal_cdi_label),
                                  cert_ctx->seal_cdi_hash_input,
                                  sizeof(cert_ctx->seal_cdi_hash_input),
                                  &cert_ctx->data.seal_cdi_key_id);
    }
}

psa_status_t derive_wrapping_key(struct cert_context_t *cert_ctx)
{
    //TODO:
    (void)cert_ctx;
    return PSA_SUCCESS;
}

psa_status_t derive_id_from_public_key(struct cert_context_t *cert_ctx)
{
    psa_status_t status;
    psa_key_attributes_t derive_key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t base_attr = PSA_KEY_ATTRIBUTES_INIT;
    size_t output_id_len;

    psa_key_id_t base_key = PSA_KEY_ID_NULL;
    psa_key_id_t derived_key_id = PSA_KEY_ID_NULL;

    psa_set_key_type(&base_attr, PSA_KEY_TYPE_DERIVE);
    psa_set_key_algorithm(&base_attr, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    psa_set_key_bits(&base_attr, PSA_BYTES_TO_BITS(cert_ctx->data.attest_pub_key_len));
    psa_set_key_usage_flags(&base_attr, PSA_KEY_USAGE_DERIVE);

    status = psa_import_key(&base_attr,
                            &cert_ctx->data.attest_pub_key[0],
                            cert_ctx->data.attest_pub_key_len,
                            &base_key);
    if (status != PSA_SUCCESS) {
        return status;
    }

    /* Derive Key attributes same as CDI attributes except the label */
    psa_set_key_type(&derive_key_attr, PSA_KEY_TYPE_RAW_DATA);
    psa_set_key_algorithm(&derive_key_attr, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    psa_set_key_bits(&derive_key_attr, PSA_BYTES_TO_BITS(DICE_ID_SIZE));
    psa_set_key_usage_flags(&derive_key_attr, PSA_KEY_USAGE_EXPORT);

    /* Perform ID derivation */
    /* Supply the ID label as an input to the key derivation */
    status = perform_derivation(base_key,
                                &derive_key_attr,
                                (uint8_t *) &id_label[0],
                                sizeof(id_label),
                                id_salt,
                                sizeof(id_salt),
                                &derived_key_id);
    if (status != PSA_SUCCESS) {
        goto err_destroy_base_key;
    }
    status = psa_export_key(derived_key_id,
                            &cert_ctx->data.cdi_id[0],
                            sizeof(cert_ctx->data.cdi_id),
                            &output_id_len);

    (void)psa_destroy_key(derived_key_id);

err_destroy_base_key:
    (void)psa_destroy_key(base_key);

    return status;
}

psa_status_t derive_cdi_id(psa_key_id_t attest_key_id, uint8_t *cdi_id,
                           size_t cdi_id_size)
{
    psa_status_t status;
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    uint8_t attest_pub_key[DPE_ATTEST_PUB_KEY_SIZE];
    size_t attest_pub_key_len;

    status = psa_export_public_key(attest_key_id, attest_pub_key,
                                   sizeof(attest_pub_key), &attest_pub_key_len);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
                                            id_salt, sizeof(id_salt));
    if (status != PSA_SUCCESS) {
        goto err_abort;
    }

    status = psa_key_derivation_input_bytes(&op,
                                            PSA_KEY_DERIVATION_INPUT_SECRET,
                                            attest_pub_key, attest_pub_key_len);
    if (status != PSA_SUCCESS) {
        goto err_abort;
    }

    status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                            (const uint8_t *)id_label,
                                            sizeof(id_label));
    if (status != PSA_SUCCESS) {
        goto err_abort;
    }

    status = psa_key_derivation_output_bytes(&op, cdi_id, cdi_id_size);
    if (status != PSA_SUCCESS) {
        goto err_abort;
    }

    return psa_key_derivation_abort(&op);

err_abort:
    (void)psa_key_derivation_abort(&op);
    return status;
}

psa_status_t get_certificate_cdi_value(const struct cert_context_t *cert_ctx,
                                       uint8_t cdi_attest_buf[DICE_CDI_SIZE],
                                       uint8_t cdi_seal_buf[DICE_CDI_SIZE])
{
    psa_status_t status;
    size_t cdi_actual_size;

    /* Query the attest CDI */
    status = psa_export_key(cert_ctx->data.attest_cdi_key_id,
                            cdi_attest_buf,
                            DICE_CDI_SIZE,
                            &cdi_actual_size);
    if (status != PSA_SUCCESS) {
        return status;
    }

    assert(cdi_actual_size == DICE_CDI_SIZE);

    /* Query the seal CDI */
    status = psa_export_key(cert_ctx->data.seal_cdi_key_id,
                            cdi_seal_buf,
                            DICE_CDI_SIZE,
                            &cdi_actual_size);

    assert(cdi_actual_size == DICE_CDI_SIZE);

    return status;
}

void destroy_certificate_context_keys(struct cert_context_t *cert_ctx)
{
    if (cert_ctx->data.attest_cdi_key_id != PSA_KEY_ID_NULL) {
        /* Remove any previously derived keys */
        (void)psa_destroy_key(cert_ctx->data.attest_cdi_key_id);
        cert_ctx->data.attest_cdi_key_id = PSA_KEY_ID_NULL;
    }

    if (cert_ctx->data.seal_cdi_key_id != PSA_KEY_ID_NULL) {
        /* Remove any previously derived keys */
        (void)psa_destroy_key(cert_ctx->data.seal_cdi_key_id);
        cert_ctx->data.seal_cdi_key_id = PSA_KEY_ID_NULL;
    }

    if (cert_ctx->data.attest_key_id != PSA_KEY_ID_NULL) {
        /* Remove any previously derived keys */
        (void)psa_destroy_key(cert_ctx->data.attest_key_id);
        cert_ctx->data.attest_key_id = PSA_KEY_ID_NULL;
    }
}
