/*
 * Copyright (c) 2023-2025, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <assert.h>
#include "dpe_certificate.h"
#include "dpe_context_mngr.h"
#include "dpe_crypto_config.h"
#include "dpe_crypto_interface.h"
#include "dpe_plat.h"
#include "qcbor/qcbor_encode.h"
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_key.h"
#include "t_cose/t_cose_sign1_sign.h"

#define ID_HEX_SIZE (2 * DICE_ID_SIZE)      /* Size of CDI encoded to ascii hex */
#define LABEL_HEX_SIZE (2 * DPE_EXTERNAL_LABEL_MAX_SIZE)

static void convert_to_ascii_hex(const uint8_t *in,
                                 size_t in_size,
                                 char *out,
                                 size_t out_size)
{
    const char hex_table[] = "0123456789abcdef";
    size_t in_pos = 0;
    size_t out_pos = 0;

    for (in_pos = 0; in_pos < in_size && out_pos < out_size; in_pos++) {
        out[out_pos++] = hex_table[(in[in_pos] & 0xF0) >> 4];
        out[out_pos++] = hex_table[in[in_pos] & 0x0F];
    }
}

static dpe_error_t t_cose_err_to_dpe_err(enum t_cose_err_t err)
{
    switch(err) {

    case T_COSE_SUCCESS:
        return DPE_NO_ERROR;

    case T_COSE_ERR_TOO_SMALL:
        return DPE_INSUFFICIENT_MEMORY;

    default:
        /* A lot of the errors are not mapped because they are
         * primarily internal errors that should never happen. They
         * end up here.
         */
        return DPE_INTERNAL_ERROR;
    }
}

static dpe_error_t certificate_encode_start(QCBOREncodeContext *cbor_enc_ctx,
                                            struct t_cose_sign1_sign_ctx *signer_ctx,
                                            psa_key_handle_t private_key)
{
    enum t_cose_err_t t_cose_err;
    struct t_cose_key attest_key;
    UsefulBufC attest_key_id = {NULL, 0};

    /* DPE Certificate is untagged COSE_Sign1 message */
    t_cose_sign1_sign_init(signer_ctx, T_COSE_OPT_OMIT_CBOR_TAG, DPE_T_COSE_ALG);

    attest_key.key.handle = private_key;

    t_cose_sign1_set_signing_key(signer_ctx, attest_key, attest_key_id);

    /* It is expected that the CBOR encoder is already initialized */

    /* This encodes and writes the cose headers to be into the CBOR context. */
    t_cose_err = t_cose_sign1_encode_parameters(signer_ctx,
                                                cbor_enc_ctx);
    if (t_cose_err) {
        return t_cose_err_to_dpe_err(t_cose_err);
    }

    QCBOREncode_OpenMap(cbor_enc_ctx);

    return DPE_NO_ERROR;
}

static void add_key_usage_claim(QCBOREncodeContext *cbor_enc_ctx)
{
    uint8_t key_usage = DPE_CERT_KEY_USAGE_CERT_SIGN;

    /* Encode key usage as byte string */
    QCBOREncode_AddBytesToMapN(cbor_enc_ctx,
                               DPE_CERT_LABEL_KEY_USAGE,
                               (UsefulBufC){ &key_usage,
                                             sizeof(key_usage) });
}

static void add_label_claim(QCBOREncodeContext *cbor_enc_ctx,
                            const uint8_t *label,
                            size_t label_size)
{
    char label_hex[LABEL_HEX_SIZE];

    /* If label is supplied, add label claim, else skip */
    if ((label != NULL) && (label_size != 0)) {
        convert_to_ascii_hex(&label[0],
                             label_size,
                             &label_hex[0],
                             sizeof(label_hex));

        /* Encode label as text string */
        QCBOREncode_AddTextToMapN(cbor_enc_ctx,
                                  DPE_CERT_LABEL_EXTERNAL_LABEL,
                                  (UsefulBufC){ &label_hex[0],
                                                label_size });
    }
}

static void add_cdi_export_claim(QCBOREncodeContext *cbor_enc_ctx,
                                 const struct cert_context_t *cert_ctx)
{
    QCBOREncode_AddBoolToMapN(cbor_enc_ctx,
                              DPE_CERT_LABEL_CDI_EXPORT,
                              cert_ctx->is_cdi_to_be_exported);
}

static void add_subject_claim(QCBOREncodeContext *cbor_enc_ctx,
                              const struct cert_context_t *cert_ctx)
{
    char cdi_id_hex[ID_HEX_SIZE];

    convert_to_ascii_hex(&cert_ctx->data.cdi_id[0],
                         sizeof(cert_ctx->data.cdi_id),
                         &cdi_id_hex[0],
                         sizeof(cdi_id_hex));
    /* Encode subject as text string */
    QCBOREncode_AddTextToMapN(cbor_enc_ctx,
                              DPE_CERT_LABEL_SUBJECT,
                              (UsefulBufC){ &cdi_id_hex[0],
                                            sizeof(cdi_id_hex) });
}

static void encode_issuer_claim(QCBOREncodeContext *cbor_enc_ctx,
                                const uint8_t *issuer,
                                size_t issuer_size)
{
    char cdi_id_hex[ID_HEX_SIZE];

    convert_to_ascii_hex(issuer,
                         issuer_size,
                         &cdi_id_hex[0],
                         sizeof(cdi_id_hex));

    /* Encode issuer as text string */
    QCBOREncode_AddTextToMapN(cbor_enc_ctx,
                              DPE_CERT_LABEL_ISSUER,
                              (UsefulBufC){ &cdi_id_hex[0],
                                            sizeof(cdi_id_hex) });
}

static dpe_error_t encode_public_key(QCBOREncodeContext *cbor_enc_ctx,
                                     psa_key_id_t attest_key_id)
{
    Q_USEFUL_BUF_MAKE_STACK_UB(cose_key_buf, MAX_ENCODED_COSE_KEY_SIZE);
    struct t_cose_key attest_key;
    struct q_useful_buf_c cose_key;
    enum t_cose_err_t cose_res;

    /* Export the public key and encodes it to be a COSE_Key object */
    attest_key.key.handle = attest_key_id;
    cose_res = t_cose_key_encode(attest_key,
                                 cose_key_buf,
                                 &cose_key);
    if (cose_res != T_COSE_SUCCESS) {
        return DPE_INTERNAL_ERROR;
    }

    QCBOREncode_AddEncoded(cbor_enc_ctx, cose_key);

    return DPE_NO_ERROR;
}

static dpe_error_t add_public_key_claim(QCBOREncodeContext *cbor_enc_ctx,
                                        psa_key_id_t attest_key_id)
{
    dpe_error_t err;

    /* COSE_Key is encoded as a map. This map is wrapped into the a
     * byte string and it is further encoded as a map.
     */
    QCBOREncode_BstrWrapInMapN(cbor_enc_ctx, DPE_CERT_LABEL_SUBJECT_PUBLIC_KEY);
    err = encode_public_key(cbor_enc_ctx, attest_key_id);
    if (err != DPE_NO_ERROR) {
        return err;
    }
    QCBOREncode_CloseBstrWrap2(cbor_enc_ctx, false, NULL);

    return DPE_NO_ERROR;
}

static dpe_error_t add_public_key_to_certificate_chain(QCBOREncodeContext *cbor_enc_ctx,
                                                       psa_key_id_t attest_key_id)
{
    dpe_error_t err;

    /* COSE_Key is encoded as a map wrapped into a byte string */
    QCBOREncode_BstrWrap(cbor_enc_ctx);
    err = encode_public_key(cbor_enc_ctx, attest_key_id);
    if (err != DPE_NO_ERROR) {
        return err;
    }
    QCBOREncode_CloseBstrWrap2(cbor_enc_ctx, false, NULL);

    return DPE_NO_ERROR;
}

static dpe_error_t certificate_encode_finish(QCBOREncodeContext *cbor_enc_ctx,
                                             struct t_cose_sign1_sign_ctx *signer_ctx,
                                             bool finish_cbor_encoding,
                                             UsefulBufC *completed_cert)
{
    QCBORError qcbor_result;
    enum t_cose_err_t cose_return_value;

    QCBOREncode_CloseMap(cbor_enc_ctx);

    /* -- Finish up the COSE_Sign1. This is where the signing happens -- */
    cose_return_value = t_cose_sign1_encode_signature(signer_ctx,
                                                      cbor_enc_ctx);
    if (cose_return_value) {
        /* Main errors are invoking the hash or signature */
        return t_cose_err_to_dpe_err(cose_return_value);
    }

    /* If only a single certificate is created then encoding can be finished.
     * Otherwise, when multiple certifcate is encoded in a raw
     * (GetCertificateChain) then encoding will be finished
     * by close_certificate_chain().
     */
    if (finish_cbor_encoding) {
       /* Finally close off the CBOR formatting and get the pointer and length
        * of the resulting COSE_Sign1.
        */
        qcbor_result = QCBOREncode_Finish(cbor_enc_ctx, completed_cert);
        if (qcbor_result == QCBOR_ERR_BUFFER_TOO_SMALL) {
            return DPE_INSUFFICIENT_MEMORY;
        } else if (qcbor_result != QCBOR_SUCCESS) {
            /* likely from array not closed, too many closes, ... */
            return DPE_INTERNAL_ERROR;
        }
    }

    return DPE_NO_ERROR;
}

static void encode_sw_component_measurements(QCBOREncodeContext *encode_ctx,
                                             struct component_context_t *component_ctx)
{
    QCBOREncode_OpenMap(encode_ctx);

    /* Encode measurement value as byte string */
    QCBOREncode_AddBytesToMapN(encode_ctx,
                               DPE_CERT_LABEL_CODE_HASH,
                               (UsefulBufC){ &component_ctx->data.measurement_value,
                                             DICE_HASH_SIZE });

    /* Encode measurement descriptor version as byte string */
    QCBOREncode_AddBytesToMapN(encode_ctx,
                               DPE_CERT_LABEL_CODE_DESCRIPTOR,
                               (UsefulBufC){ &component_ctx->data.measurement_descriptor,
                                             component_ctx->data.measurement_descriptor_size });

    /* Encode signer ID Hash as byte string */
    QCBOREncode_AddBytesToMapN(encode_ctx,
                               DPE_CERT_LABEL_AUTHORITY_HASH,
                               (UsefulBufC){ &component_ctx->data.signer_id,
                                             DICE_HASH_SIZE });

    /* Encode signer ID descriptor as byte string */
    QCBOREncode_AddBytesToMapN(encode_ctx,
                               DPE_CERT_LABEL_AUTHORITY_DESCRIPTOR,
                               (UsefulBufC){ &component_ctx->data.signer_id_descriptor,
                                             component_ctx->data.signer_id_descriptor_size });

    if (component_ctx->data.config_descriptor_size > 0) {
        /* Encode config descriptor as byte string */
        QCBOREncode_AddBytesToMapN(encode_ctx,
                                   DPE_CERT_LABEL_CONFIGURATION_DESCRIPTOR,
                                   (UsefulBufC){ &component_ctx->data.config_descriptor,
                                                 component_ctx->data.config_descriptor_size });
        /* Encode config value as byte string */
        QCBOREncode_AddBytesToMapN(encode_ctx,
                                   DPE_CERT_LABEL_CONFIGURATION_HASH,
                                   (UsefulBufC){ &component_ctx->data.config_value,
                                                 DICE_INLINE_CONFIG_SIZE });
    } else {
        /* Encode config value as byte string */
        QCBOREncode_AddBytesToMapN(encode_ctx,
                                   DPE_CERT_LABEL_CONFIGURATION_DESCRIPTOR,
                                   (UsefulBufC){ &component_ctx->data.config_value,
                                                 DICE_INLINE_CONFIG_SIZE });
    }

    /* Encode mode value as byte string */
    QCBOREncode_AddBytesToMapN(encode_ctx,
                               DPE_CERT_LABEL_MODE,
                               (UsefulBufC){ &component_ctx->data.mode,
                                             sizeof(DiceMode) });

    QCBOREncode_CloseMap(encode_ctx);
}

static dpe_error_t encode_sw_components_array(const struct cert_context_t *cert_ctx,
                                              QCBOREncodeContext *cbor_enc_ctx)
{
    int i;
    struct component_context_t *component_ctx;

    /* Open array which stores SW components claims. */
    QCBOREncode_OpenArrayInMapN(cbor_enc_ctx, DPE_CERT_LABEL_SW_COMPONENTS);

    /* Add elements to the array if there is any */
    for (i = 0; i < cert_ctx->linked_components.count; i++) {
        component_ctx = cert_ctx->linked_components.ptr[i];
        if (component_ctx == NULL) {
            return DPE_INTERNAL_ERROR;
        }
        encode_sw_component_measurements(cbor_enc_ctx, component_ctx);
    }

    /* Close array which stores SW components claims. */
    QCBOREncode_CloseArray(cbor_enc_ctx);

    return DPE_NO_ERROR;
}

static dpe_error_t add_issuer_claim(QCBOREncodeContext *cbor_enc_ctx,
                                    const struct cert_context_t *cert_ctx,
                                    psa_key_id_t root_attest_key_id,
                                    const struct cert_context_t *parent_cert_ctx)
{
    uint8_t rot_cdi_id[DICE_ID_SIZE];

    if (cert_ctx->is_rot_cert_ctx) {
        /* For the RoT certificate, issuer id is derived from the root attestation key */
        if (derive_cdi_id(root_attest_key_id, rot_cdi_id,
                          sizeof(rot_cdi_id)) != PSA_SUCCESS) {
            return DPE_INTERNAL_ERROR;
        }

        encode_issuer_claim(cbor_enc_ctx,
                            rot_cdi_id,
                            sizeof(rot_cdi_id));
    } else {
        encode_issuer_claim(cbor_enc_ctx,
                            parent_cert_ctx->data.cdi_id,
                            sizeof(parent_cert_ctx->data.cdi_id));
    }

    return DPE_NO_ERROR;
}

static dpe_error_t encode_certificate_internal(const struct cert_context_t *cert_ctx,
                                               QCBOREncodeContext *cbor_enc_ctx,
                                               bool finish_cbor_encoding,
                                               size_t *cert_actual_size)
{
    struct t_cose_sign1_sign_ctx signer_ctx;
    struct cert_context_t *parent_cert_ctx;
    dpe_error_t err;
    UsefulBufC completed_cert;
    psa_key_id_t attest_key_id;

    /* Valid options: true & !NULL OR false & NULL */
    assert(finish_cbor_encoding ^ (cert_actual_size == NULL));

    parent_cert_ctx = cert_ctx->parent_cert_ptr;
    assert(parent_cert_ctx != NULL);

    /* The RoT certificate is signed by the provisioned attestation key,
     * all other certificates are signed by the parent certificate's attestation key.
     */
    if (cert_ctx->is_rot_cert_ctx) {
        attest_key_id = dpe_plat_get_root_attest_key_id();
    } else {
        attest_key_id = parent_cert_ctx->data.attest_key_id;
    }

    /* Get started creating the certificate. This sets up the CBOR and
     * COSE contexts which causes the COSE headers to be constructed.
     */
    err = certificate_encode_start(cbor_enc_ctx,
                                   &signer_ctx,
                                   attest_key_id);
    if (err != DPE_NO_ERROR) {
        return err;
    }

    /* Add all the required claims */
    /* Add issuer/authority claim */
    err = add_issuer_claim(cbor_enc_ctx, cert_ctx, attest_key_id, parent_cert_ctx);
    if (err != DPE_NO_ERROR) {
        return err;
    }

    /* Add subject claim */
    add_subject_claim(cbor_enc_ctx, cert_ctx);

    /* Encode all firmware measurements for the components linked to this
     * certificate context
     */
    //TODO:
    /* It is not yet defined in the open-dice profile how to represent
     * multiple SW components in a single certificate; In current implementation,
     * an array is created for all the components' measurements and within the
     * array, there are multiple maps, one for each SW component
     */
    err = encode_sw_components_array(cert_ctx, cbor_enc_ctx);
    if (err != DPE_NO_ERROR) {
        return err;
    }

    /* Add label claim */
    add_label_claim(cbor_enc_ctx,
                    &cert_ctx->data.external_key_deriv_label[0],
                    cert_ctx->data.external_key_deriv_label_len);

    /* Add public key claim */
    err = add_public_key_claim(cbor_enc_ctx, cert_ctx->data.attest_key_id);
    if (err != DPE_NO_ERROR) {
        return err;
    }

    /* Add key usage claim */
    add_key_usage_claim(cbor_enc_ctx);

    /* Add CDI exported claim */
    if (cert_ctx->is_cdi_to_be_exported) {
        add_cdi_export_claim(cbor_enc_ctx, cert_ctx);
    }

    /* Finish up creating the certificate. This is where the actual signature
     * is generated.
     */
    err = certificate_encode_finish(cbor_enc_ctx, &signer_ctx,
                                    finish_cbor_encoding, &completed_cert);
    if (err != DPE_NO_ERROR) {
        return err;
    }

    /* Update the final size of the certificate if requested */
    if (cert_actual_size != NULL) {
        *cert_actual_size = completed_cert.len;
    }

    return err;
}

dpe_error_t encode_certificate(const struct cert_context_t *cert_ctx,
                               uint8_t *cert_buf,
                               size_t cert_buf_size,
                               size_t *cert_actual_size)
{
    QCBOREncodeContext cbor_enc_ctx;

    QCBOREncode_Init(&cbor_enc_ctx,
                     (UsefulBuf){ cert_buf,
                                  cert_buf_size });

    /* Only a single certificate is encoded */
    return encode_certificate_internal(cert_ctx, &cbor_enc_ctx,
                                       true, cert_actual_size);
}

dpe_error_t store_certificate(const struct cert_context_t *cert_ctx)
{
    //TODO:
    (void)cert_ctx;
    return DPE_NO_ERROR;
}

static void open_certificate_chain(QCBOREncodeContext *cbor_enc_ctx,
                                   uint8_t *cert_chain_buf,
                                   size_t cert_chain_buf_size)
{
    /* Set up encoding context with output buffer. */
    QCBOREncode_Init(cbor_enc_ctx,
                     (UsefulBuf){ &cert_chain_buf[0],
                                  cert_chain_buf_size });
    QCBOREncode_OpenArray(cbor_enc_ctx);
}

static dpe_error_t close_certificate_chain(QCBOREncodeContext *cbor_enc_ctx,
                                           size_t *cert_chain_actual_size)
{
    QCBORError encode_error;
    UsefulBufC completed_cert_chain;

    QCBOREncode_CloseArray(cbor_enc_ctx);

    encode_error = QCBOREncode_Finish(cbor_enc_ctx,
                                      &completed_cert_chain);

    /* Check for any encoding errors. */
    if (encode_error == QCBOR_ERR_BUFFER_TOO_SMALL) {
        return DPE_INSUFFICIENT_MEMORY;
    } else if (encode_error != QCBOR_SUCCESS) {
        return DPE_INTERNAL_ERROR;
    }

    *cert_chain_actual_size = completed_cert_chain.len;

    return DPE_NO_ERROR;
}

static dpe_error_t add_root_attestation_public_key(QCBOREncodeContext *cbor_enc_ctx)
{
    psa_key_id_t attest_key_id = dpe_plat_get_root_attest_key_id();
    dpe_error_t err;

    err = add_public_key_to_certificate_chain(cbor_enc_ctx, attest_key_id);
    if (err != DPE_NO_ERROR) {
        return err;
    }

    return DPE_NO_ERROR;
}

dpe_error_t get_certificate_chain(const struct cert_context_t *cert_ctx,
                                  uint8_t *cert_chain_buf,
                                  size_t cert_chain_buf_size,
                                  size_t *cert_chain_actual_size)
{
    QCBOREncodeContext cbor_enc_ctx;
    dpe_error_t err;
    int i;
    const struct cert_context_t *cert_chain[MAX_NUM_OF_CERTIFICATES];
    uint16_t cert_cnt = 0;

    open_certificate_chain(&cbor_enc_ctx,
                           cert_chain_buf,
                           cert_chain_buf_size);

    /* Add DICE/Root public key (IAK public key) as the first entry of array */
    err = add_root_attestation_public_key(&cbor_enc_ctx);
    if (err != DPE_NO_ERROR) {
        return err;
    }

    /* Loop from leaf to the RoT certificate & save all the linked certificates in this chain */
    while ((cert_ctx != NULL) && (cert_cnt < MAX_NUM_OF_CERTIFICATES)) {

        /* Save certificate context pointer */
        cert_chain[cert_cnt++] = cert_ctx;

        if (cert_ctx->is_rot_cert_ctx) {
            /* This is the end of chain */
            break;
        }

        /* Move to the parent certificate context */
        cert_ctx = cert_ctx->parent_cert_ptr;
    }

    /* Add certificate from RoT to leaf certificate order */
    for (i = cert_cnt - 1; i >= 0; i--) {
        /* Might multiple certificate is encoded */
        err = encode_certificate_internal(cert_chain[i], &cbor_enc_ctx,
                                          false, NULL);
        if (err != DPE_NO_ERROR) {
            return err;
        }
    }

    return close_certificate_chain(&cbor_enc_ctx,
                                   cert_chain_actual_size);
}

dpe_error_t encode_cdi(const uint8_t cdi_attest_buf[DICE_CDI_SIZE],
                       const uint8_t cdi_seal_buf[DICE_CDI_SIZE],
                       uint8_t *encoded_cdi_buf,
                       size_t encoded_cdi_buf_size,
                       size_t *encoded_cdi_actual_size)
{
    QCBOREncodeContext encode_ctx;
    QCBORError encode_err;
    UsefulBufC out;

    QCBOREncode_Init(&encode_ctx, (UsefulBuf){ encoded_cdi_buf, encoded_cdi_buf_size });
    QCBOREncode_OpenMap(&encode_ctx);

    /* Encode CDI value as byte string */
    QCBOREncode_AddBytesToMapN(&encode_ctx,
                               DPE_LABEL_CDI_ATTEST,
                               (UsefulBufC){ cdi_attest_buf, DICE_CDI_SIZE });

    QCBOREncode_AddBytesToMapN(&encode_ctx,
                               DPE_LABEL_CDI_SEAL,
                               (UsefulBufC){ cdi_seal_buf, DICE_CDI_SIZE });

    QCBOREncode_CloseMap(&encode_ctx);
    encode_err = QCBOREncode_Finish(&encode_ctx, &out);

    /* Check for any encoding errors. */
    if (encode_err == QCBOR_ERR_BUFFER_TOO_SMALL) {
        return DPE_INSUFFICIENT_MEMORY;
    } else if (encode_err != QCBOR_SUCCESS) {
        return DPE_INTERNAL_ERROR;
    }

    *encoded_cdi_actual_size = out.len;

    return DPE_NO_ERROR;
}
