/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <assert.h>
#include "dpe_certificate.h"
#include "dpe_context_mngr.h"
#include "dpe_crypto_config.h"
#include "dpe_crypto_interface.h"
#include "qcbor/qcbor_encode.h"
#include "t_cose_common.h"
#include "t_cose_sign1_sign.h"

#define ID_HEX_SIZE (2 * DICE_ID_SIZE)      /* Size of CDI encoded to ascii hex */

struct dpe_cert_encode_ctx {
    QCBOREncodeContext           cbor_enc_ctx;
    struct t_cose_sign1_sign_ctx signer_ctx;
};

static void convert_to_ascii_hex(const uint8_t *in,
                                 size_t in_size,
                                 char *out,
                                 size_t out_size)
{
    const char hex_table[] = "0123456789abcdef";
    size_t in_pos = 0;
    size_t out_pos = 0;

    for (in_pos = 0; in_pos < in_size && out_pos < out_size; in_pos++) {
        out[out_pos++] = hex_table[(in[in_pos] & 0xF0 >> 4)];
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

static dpe_error_t certificate_encode_start(struct dpe_cert_encode_ctx *me,
                                            const UsefulBuf out_buf,
                                            psa_key_handle_t private_key)
{
    enum t_cose_err_t t_cose_err;
    struct t_cose_key attest_key;
    UsefulBufC attest_key_id = {NULL, 0};

    /* DPE Certificate is untagged COSE_Sign1 message */
    t_cose_sign1_sign_init(&(me->signer_ctx), T_COSE_OPT_OMIT_CBOR_TAG, DPE_T_COSE_ALG);

    attest_key.crypto_lib = T_COSE_CRYPTO_LIB_PSA;
    attest_key.k.key_handle = private_key;

    t_cose_sign1_set_signing_key(&(me->signer_ctx),
                                 attest_key,
                                 attest_key_id);

    /* Spin up the CBOR encoder */
    QCBOREncode_Init(&(me->cbor_enc_ctx), out_buf);

    /* This will cause the cose headers to be encoded and written into
     *  out_buf using me->cbor_enc_ctx
     */
    t_cose_err = t_cose_sign1_encode_parameters(&(me->signer_ctx),
                                                &(me->cbor_enc_ctx));
    if (t_cose_err) {
        return t_cose_err_to_dpe_err(t_cose_err);
    }

    QCBOREncode_OpenMap(&(me->cbor_enc_ctx));

    return DPE_NO_ERROR;
}

static void add_key_usage_claim(struct dpe_cert_encode_ctx *me)
{
    uint8_t key_usage = DPE_CERT_KEY_USAGE_CERT_SIGN;

    /* Encode key usage as byte string */
    QCBOREncode_AddBytesToMapN(&me->cbor_enc_ctx,
                               DPE_CERT_LABEL_KEY_USAGE,
                               (UsefulBufC){ &key_usage,
                                             sizeof(key_usage) });
}

static void add_subject_claim(struct dpe_cert_encode_ctx *me,
                              struct layer_context_t *layer_ctx)
{
    char cdi_id_hex[ID_HEX_SIZE];

    convert_to_ascii_hex(&layer_ctx->data.cdi_id[0],
                         sizeof(layer_ctx->data.cdi_id),
                         &cdi_id_hex[0],
                         sizeof(cdi_id_hex));
    /* Encode subject as text string */
    QCBOREncode_AddTextToMapN(&me->cbor_enc_ctx,
                              DPE_CERT_LABEL_SUBJECT,
                              (UsefulBufC){ &cdi_id_hex[0],
                                            sizeof(cdi_id_hex) });
}

static void add_issuer_claim(struct dpe_cert_encode_ctx *me,
                             const struct layer_context_t *parent_layer_ctx)
{

    char cdi_id_hex[ID_HEX_SIZE];

    convert_to_ascii_hex(&parent_layer_ctx->data.cdi_id[0],
                         sizeof(parent_layer_ctx->data.cdi_id),
                         &cdi_id_hex[0],
                         sizeof(cdi_id_hex));

    /* Encode issuer as text string */
    QCBOREncode_AddTextToMapN(&me->cbor_enc_ctx,
                              DPE_CERT_LABEL_ISSUER,
                              (UsefulBufC){ &cdi_id_hex[0],
                                            sizeof(cdi_id_hex) });
}

static void add_public_key_claim(struct dpe_cert_encode_ctx *me,
                                 const struct layer_context_t *layer_ctx)
{
    /* As per RFC8152 */
    const int64_t cose_key_type_value = DPE_T_COSE_KEY_TYPE_VAL;
    const int64_t cose_key_ops_value = DPE_T_COSE_KEY_OPS_VAL;
    const int64_t cose_key_ec2_curve_value = DPE_T_COSE_KEY_EC2_CURVE_VAL;
    const int64_t cose_key_alg_value = DPE_T_COSE_KEY_ALG_VAL;
    size_t pub_key_size = layer_ctx->data.attest_pub_key_len;
    UsefulBufC wrapped;

    /* Cose key is encoded as a map wrapped into a byte string */
    QCBOREncode_BstrWrapInMapN(&me->cbor_enc_ctx, DPE_CERT_LABEL_SUBJECT_PUBLIC_KEY);
    QCBOREncode_OpenMap(&me->cbor_enc_ctx);

    /* Add the key type as int */
    QCBOREncode_AddInt64ToMapN(&me->cbor_enc_ctx,
                               DPE_CERT_LABEL_COSE_KEY_TYPE,
                               cose_key_type_value);

    /* Add the algorithm as int */
    QCBOREncode_AddInt64ToMapN(&me->cbor_enc_ctx,
                               DPE_CERT_LABEL_COSE_KEY_ALG,
                               cose_key_alg_value);

    /* Add the key operation as [+ (tstr/int)] */
    QCBOREncode_OpenArrayInMapN(&me->cbor_enc_ctx, DPE_CERT_LABEL_COSE_KEY_OPS);
    QCBOREncode_AddInt64(&me->cbor_enc_ctx,
                               cose_key_ops_value);
    QCBOREncode_CloseArray(&me->cbor_enc_ctx);

    /* Add the curve */
    QCBOREncode_AddInt64ToMapN(&me->cbor_enc_ctx,
                               DPE_CERT_LABEL_COSE_KEY_EC2_CURVE,
                               cose_key_ec2_curve_value);

    /* Add the subject public key x and y coordinates */
    QCBOREncode_AddBytesToMapN(&me->cbor_enc_ctx,
                               DPE_CERT_LABEL_COSE_KEY_EC2_X,
                               (UsefulBufC){ &layer_ctx->data.attest_pub_key[0],
                                             pub_key_size/2 });

    QCBOREncode_AddBytesToMapN(&me->cbor_enc_ctx,
                               DPE_CERT_LABEL_COSE_KEY_EC2_Y,
                               (UsefulBufC){ &layer_ctx->data.attest_pub_key[pub_key_size/2],
                                             pub_key_size/2 });

    QCBOREncode_CloseMap(&me->cbor_enc_ctx);
    QCBOREncode_CloseBstrWrap2(&me->cbor_enc_ctx, true, &wrapped);

    assert(wrapped.len <= DICE_MAX_ENCODED_PUBLIC_KEY_SIZE);
}

static dpe_error_t certificate_encode_finish(struct dpe_cert_encode_ctx *me,
                                             UsefulBufC *completed_cert)
{
    QCBORError qcbor_result;
    enum t_cose_err_t cose_return_value;

    QCBOREncode_CloseMap(&(me->cbor_enc_ctx));

    /* -- Finish up the COSE_Sign1. This is where the signing happens -- */
    cose_return_value = t_cose_sign1_encode_signature(&(me->signer_ctx),
                                                      &(me->cbor_enc_ctx));
    if (cose_return_value) {
        /* Main errors are invoking the hash or signature */
        return t_cose_err_to_dpe_err(cose_return_value);
    }

    /* Finally close off the CBOR formatting and get the pointer and length
     * of the resulting COSE_Sign1
     */
    qcbor_result = QCBOREncode_Finish(&(me->cbor_enc_ctx), completed_cert);
    if (qcbor_result == QCBOR_ERR_BUFFER_TOO_SMALL) {
        return DPE_INSUFFICIENT_MEMORY;

    } else if (qcbor_result != QCBOR_SUCCESS) {
        /* likely from array not closed, too many closes, ... */
        return DPE_INTERNAL_ERROR;

    } else {
        return DPE_NO_ERROR;
    }
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

static void encode_layer_sw_components_array(uint16_t layer_idx,
                                             struct dpe_cert_encode_ctx *me)
{
    int i, cnt;
    struct component_context_t *component_ctx;

    for (i = 0, cnt = 0; i < MAX_NUM_OF_COMPONENTS; i++) {
        component_ctx = get_component_if_linked_to_layer(layer_idx, i);
        if (component_ctx != NULL) {
            /* This component belongs to current layer */
            cnt++;

            if (cnt == 1) {
                /* Open array which stores SW components claims. */
                QCBOREncode_OpenArrayInMapN(&me->cbor_enc_ctx,
                                            DPE_CERT_LABEL_SW_COMPONENTS);
            }
            encode_sw_component_measurements(&me->cbor_enc_ctx, component_ctx);
        }
    }

    if (cnt != 0) {
        /* Close array which stores SW components claims. */
        QCBOREncode_CloseArray(&me->cbor_enc_ctx);
    }
}


dpe_error_t encode_layer_certificate(uint16_t layer_idx,
                                     struct layer_context_t *layer_ctx,
                                     const struct layer_context_t *parent_layer_ctx)
{
    dpe_error_t err;
    struct dpe_cert_encode_ctx dpe_cert_ctx;
    UsefulBuf cert;
    UsefulBufC completed_cert;

    psa_key_id_t attest_key_id = parent_layer_ctx->data.attest_key_id;

    /* Get started creating the certificate/token. This sets up the CBOR and
     * COSE contexts which causes the COSE headers to be constructed.
     */
    cert.ptr = &layer_ctx->data.cert_buf[0];
    cert.len = sizeof(layer_ctx->data.cert_buf);

    err = certificate_encode_start(&dpe_cert_ctx,
                                   cert,
                                   attest_key_id);
    if (err != DPE_NO_ERROR) {
        return err;
    }

    /* Add all the required claims */
    /* Add issuer/authority claim */
    add_issuer_claim(&dpe_cert_ctx, parent_layer_ctx);

    /* Add subject claim */
    add_subject_claim(&dpe_cert_ctx, layer_ctx);

    /* Encode all firmware measurements for the components linked to this layer */
    //TODO:
    /* It is not yet defined in the open-dice profile how to represent
     * multiple SW components in a single certificate; In current implementation,
     * an array is created for all the components' measurements and within the
     * array, there are multiple maps, one for each SW component
     */
    encode_layer_sw_components_array(layer_idx, &dpe_cert_ctx);

    /* Add public key claim */
    add_public_key_claim(&dpe_cert_ctx, layer_ctx);

    /* Add key usage claim */
    add_key_usage_claim(&dpe_cert_ctx);

    /* Finish up creating the token. This is where the actual signature
     * is generated. This finishes up the CBOR encoding too.
     */
    err = certificate_encode_finish(&dpe_cert_ctx, &completed_cert);
    if (err != DPE_NO_ERROR) {
        return err;
    }

    /* Update the final size of the token/certificate */
    layer_ctx->data.cert_buf_len = completed_cert.len;

    return err;
}

dpe_error_t store_layer_certificate(struct layer_context_t *layer_ctx)
{
    //TODO:
    (void)layer_ctx;
    return DPE_NO_ERROR;
}
