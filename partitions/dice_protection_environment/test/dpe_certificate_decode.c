/*
 * Copyright (c) 2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <assert.h>
#include "../dpe_certificate_common.h"
#include "../dpe_crypto_config.h"
#include "dpe_certificate_decode.h"
#include "dpe_certificate_log.h"
#include "psa/crypto.h"
#include "psa/error.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"
#include "t_cose_sign1_verify.h"
#include "test_framework.h"

/* Uncomment this define to print the certificate chain */
//#define PRINT_CERT_CHAIN

#define COSE_SIGN1_ARRAY_LEN    4

static QCBORError get_array_len(QCBORItem *item, int *array_len)
{
    if (item->uDataType != QCBOR_TYPE_ARRAY) {
        return QCBOR_ERR_UNEXPECTED_TYPE;
    }

    *array_len = item->val.uCount;

    return QCBOR_SUCCESS;
}

/*
 * TODO:
 *     - Determine key_type and key_alg from COSE_Key
 */
static QCBORError get_public_key(UsefulBufC cose_key,
                                 UsefulOutBuf *pub_key_buf,
                                 UsefulBufC *pub_key)
{
    QCBORDecodeContext decode_ctx;
    QCBORError qcbor_err;
    UsefulBufC coordinate = { NULL, 0 };

    UsefulOutBuf_Reset(pub_key_buf);

    QCBORDecode_Init(&decode_ctx, cose_key, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_EnterMap(&decode_ctx, NULL);
    /*
     * From psa/crypto.h:
     *
     * For other elliptic curve public keys (key types for which
     *   #PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY is true), the format is the uncompressed
     *   representation defined by SEC1 &sect;2.3.3 as the content of an ECPoint.
     *   Let `m` be the bit size associated with the curve, i.e. the bit size of
     *   `q` for a curve over `F_q`. The representation consists of:
     *      - The byte 0x04;
     *      - `x_P` as a `ceiling(m/8)`-byte string, big-endian;
     *      - `y_P` as a `ceiling(m/8)`-byte string, big-endian.
     */
    UsefulOutBuf_AppendByte(pub_key_buf, 0x04);

    QCBORDecode_GetByteStringInMapN(&decode_ctx,
                                    DPE_CERT_LABEL_COSE_KEY_EC2_X,
                                    &coordinate);
    UsefulOutBuf_AppendUsefulBuf(pub_key_buf, coordinate);

    QCBORDecode_GetByteStringInMapN(&decode_ctx,
                                    DPE_CERT_LABEL_COSE_KEY_EC2_Y,
                                    &coordinate);
    UsefulOutBuf_AppendUsefulBuf(pub_key_buf, coordinate);

    QCBORDecode_ExitMap(&decode_ctx);

    qcbor_err = QCBORDecode_Finish(&decode_ctx);
    if (qcbor_err != QCBOR_SUCCESS) {
        return qcbor_err;
    }

    *pub_key = UsefulOutBuf_OutUBuf(pub_key_buf);

    return QCBOR_SUCCESS;
}

static QCBORError get_next_certificate(QCBORDecodeContext *decode_ctx,
                                       UsefulBufC *cert_buf)
{
    QCBORError qcbor_err;
    QCBORItem item;
    int array_len;
    UsefulBufC out = { NULL, 0 };
    int prev_cursor = UsefulInputBuf_Tell(&decode_ctx->InBuf);

    cert_buf->ptr = UsefulInputBuf_GetBytes(&decode_ctx->InBuf, 0);

    QCBORDecode_EnterArray(decode_ctx, &item);

    qcbor_err = get_array_len(&item, &array_len);
    if (qcbor_err != QCBOR_SUCCESS) {
        return qcbor_err;
    }

    if (array_len != COSE_SIGN1_ARRAY_LEN) {
        return QCBOR_ERR_UNSUPPORTED;
    }

    /* Consume the protected header */
    QCBORDecode_GetByteString(decode_ctx, &out);

    /* Consume the unprotected header */
    QCBORDecode_EnterMap(decode_ctx, NULL);
    QCBORDecode_ExitMap(decode_ctx);

    /* Consume the payload */
    QCBORDecode_GetByteString(decode_ctx, &out);

    /* Consume the signature */
    QCBORDecode_GetByteString(decode_ctx, &out);

    QCBORDecode_ExitArray(decode_ctx);

    qcbor_err = QCBORDecode_GetError(decode_ctx);
    if (qcbor_err != QCBOR_SUCCESS) {
        return qcbor_err;
    }

    cert_buf->len = UsefulInputBuf_Tell(&decode_ctx->InBuf) - prev_cursor;

    return QCBOR_SUCCESS;
}

static QCBORError decode_sw_components(QCBORDecodeContext *decode_ctx,
                                       struct certificate *cert)
{
    QCBORError qcbor_err;
    QCBORItem item;
    struct component *curr_component;

    QCBORDecode_EnterArrayFromMapN(decode_ctx, DPE_CERT_LABEL_SW_COMPONENTS);

    while (true) {
        QCBORDecode_VPeekNext(decode_ctx, &item);

        qcbor_err = QCBORDecode_GetAndResetError(decode_ctx);
        if (qcbor_err == QCBOR_ERR_NO_MORE_ITEMS) {
            /* Reached the end of the array, all item was consumed */
            break;
        } else if (qcbor_err != QCBOR_SUCCESS) {
            return qcbor_err;
        }

        QCBORDecode_EnterMap(decode_ctx, NULL);

        assert(cert->component_cnt < MAX_SW_COMPONENT_NUM);
        curr_component = &cert->component_arr[cert->component_cnt];

        QCBORDecode_GetByteStringInMapN(decode_ctx,
                                        DPE_CERT_LABEL_CODE_HASH,
                                        &curr_component->code_hash);

        QCBORDecode_GetByteStringInMapN(decode_ctx,
                                        DPE_CERT_LABEL_AUTHORITY_HASH,
                                        &curr_component->authority_hash);

        QCBORDecode_GetByteStringInMapN(decode_ctx,
                                        DPE_CERT_LABEL_CODE_DESCRIPTOR,
                                        &curr_component->code_descriptor);

        QCBORDecode_ExitMap(decode_ctx);

        /* Variable number of components can be encoded into a single cert */
        cert->component_cnt++;
    }

    QCBORDecode_ExitArray(decode_ctx);

    return QCBOR_SUCCESS;
}

static QCBORError decode_payload(QCBORDecodeContext *decode_ctx,
                                 struct certificate *cert)
{
    QCBORError qcbor_err;

    QCBORDecode_EnterBstrWrapped(decode_ctx, QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);

    QCBORDecode_EnterMap(decode_ctx, NULL);

    /* Public key to verify the next certificate in the chain */
    QCBORDecode_GetByteStringInMapN(decode_ctx,
                                    DPE_CERT_LABEL_SUBJECT_PUBLIC_KEY,
                                    &cert->pub_key);

    QCBORDecode_GetTextStringInMapN(decode_ctx,
                                    DPE_CERT_LABEL_ISSUER,
                                    &cert->issuer);

    QCBORDecode_GetTextStringInMapN(decode_ctx,
                                    DPE_CERT_LABEL_SUBJECT,
                                    &cert->subject);

    QCBORDecode_GetByteStringInMapN(decode_ctx,
                                    DPE_CERT_LABEL_KEY_USAGE,
                                    &cert->key_usage);

    /* So far the mandatory claims was consumed */
    qcbor_err = QCBORDecode_GetError(decode_ctx);
    if (qcbor_err != QCBOR_SUCCESS) {
        return qcbor_err;
    }

    /* Continue with the optional claims */
    QCBORDecode_GetByteStringInMapN(decode_ctx,
                                    DPE_CERT_LABEL_EXTERNAL_LABEL,
                                    &cert->external_label);
    qcbor_err = QCBORDecode_GetAndResetError(decode_ctx);
    if (qcbor_err != QCBOR_SUCCESS && qcbor_err != QCBOR_ERR_LABEL_NOT_FOUND) {
        return qcbor_err;
    }

    QCBORDecode_GetBoolInMapN(decode_ctx,
                              DPE_CERT_LABEL_CDI_EXPORT,
                              &cert->cdi_export.value);
    qcbor_err = QCBORDecode_GetAndResetError(decode_ctx);
    if (qcbor_err == QCBOR_ERR_LABEL_NOT_FOUND) {
        cert->cdi_export.presence = false;
    } else if (qcbor_err != QCBOR_SUCCESS) {
        return qcbor_err;
    }

    /* Continue with the SW_COMPONENTS array */
    qcbor_err = decode_sw_components(decode_ctx, cert);
    if (qcbor_err != QCBOR_SUCCESS) {
        return qcbor_err;
    }

    QCBORDecode_ExitMap(decode_ctx);
    QCBORDecode_ExitBstrWrapped(decode_ctx);

    return QCBOR_SUCCESS;
}

static QCBORError verify_encoding(UsefulBufC cert_buf, struct certificate *cert)
{
    QCBORDecodeContext decode_ctx;
    QCBORError qcbor_err;
    QCBORItem item;
    int array_len;

    QCBORDecode_Init(&decode_ctx, cert_buf, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterArray(&decode_ctx, &item);
    qcbor_err = get_array_len(&item, &array_len);
    if (qcbor_err != QCBOR_SUCCESS) {
        return qcbor_err;
    }

    if (array_len != COSE_SIGN1_ARRAY_LEN) {
        return QCBOR_ERR_UNSUPPORTED;
    }

    /* Get the protected header */
    QCBORDecode_GetByteString(&decode_ctx, &cert->protected_header);

    /* Consume the unprotected header */
    QCBORDecode_EnterMap(&decode_ctx, NULL);
    QCBORDecode_ExitMap(&decode_ctx);

    /* Get the payload */
    qcbor_err = decode_payload(&decode_ctx, cert);
    if (qcbor_err != QCBOR_SUCCESS) {
        return qcbor_err;
    }

    /* Get the signature */
    QCBORDecode_GetByteString(&decode_ctx, &cert->signature);

    QCBORDecode_ExitArray(&decode_ctx);

    qcbor_err = QCBORDecode_GetError(&decode_ctx);
    if (qcbor_err != QCBOR_SUCCESS) {
        return qcbor_err;
    }

    return QCBOR_SUCCESS;
}

static enum t_cose_err_t verify_signature(UsefulBufC cert_buf,
                                          psa_key_id_t pub_key_id)
{
    enum t_cose_err_t              t_cose_error;
    struct t_cose_sign1_verify_ctx verify_ctx;
    struct t_cose_key              crypto_key;
    UsefulBufC payload;

    t_cose_sign1_verify_init(&verify_ctx, 0); /* T_COSE_OPT_DECODE_ONLY */

    crypto_key.crypto_lib = T_COSE_CRYPTO_LIB_PSA;
    crypto_key.k.key_handle = pub_key_id;

    t_cose_sign1_set_verification_key(&verify_ctx, crypto_key);
    t_cose_error =  t_cose_sign1_verify(&verify_ctx,
                                        cert_buf, /* COSE_Sign1 to verify */
                                        &payload,
                                        NULL);    /* Don't return parameters */
    return t_cose_error;
}

/*
 * Returns:
 *  - SUCCESS      :  0
 *  - QCBOR_ERR_*  : -1
 *  - T_COSE_ERR_* : -2
 */
int verify_certificate(UsefulBufC cert_buf,
                       psa_key_id_t pub_key_id,
                       struct certificate *cert)
{
    enum t_cose_err_t t_cose_err;
    QCBORError qcbor_err;

    qcbor_err = verify_encoding(cert_buf, cert);
    if (qcbor_err != QCBOR_SUCCESS) {
        return -1;
    }

    /* If the corresponding public key is not known then only verify the
     * certificate's structure.
     */
    if (pub_key_id != PSA_KEY_ID_NULL ) {
        t_cose_err = verify_signature(cert_buf, pub_key_id);
        if (t_cose_err != T_COSE_SUCCESS) {
            return -2;
        }
    }

    return 0;
}

/*
 * TODO:
 *     - Determine key_type and key_alg from COSE_Key
 */
static psa_status_t register_pub_key(UsefulBufC pub_key,
                                     psa_key_id_t *pub_key_id)
{
    psa_status_t psa_err;
    psa_key_attributes_t key_attributes;
    psa_key_type_t key_type = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1);
    psa_algorithm_t key_alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);

    key_attributes = psa_key_attributes_init();

    /* Set the algorithm and operations the key can be used with / for */
    psa_set_key_usage_flags(&key_attributes, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&key_attributes, key_alg);

    psa_set_key_type(&key_attributes, key_type);

    psa_err = psa_import_key(&key_attributes,
                              pub_key.ptr,
                              pub_key.len,
                              pub_key_id);

    return psa_err;
}

inline psa_status_t unregister_pub_key(psa_key_id_t pub_key_id)
{
    psa_status_t psa_err;

    psa_err = psa_destroy_key(pub_key_id);

    return psa_err;
}

static psa_status_t update_public_key(UsefulBufC pub_key,
                                      psa_key_id_t *pub_key_id)
{
    psa_status_t psa_err;

    psa_err = unregister_pub_key(*pub_key_id);
    if (psa_err != PSA_SUCCESS) {
        return psa_err;
    }

    psa_err = register_pub_key(pub_key, pub_key_id);

    return psa_err;
}

/*
 * DiceCertChain = [
 *     COSE_Key,         ; Root public key
 *     + COSE_Sign1,     ; DICE chain entries
 * ]
 *
 * Returns:
 *  - SUCCESS      :  0
 *  - QCBOR_ERR_*  : -1
 *  - T_COSE_ERR_* : -2
 *  - PSA_ERROR_*  : -3
 *
 */
int verify_certificate_chain(UsefulBufC cert_chain_buf,
                             struct certificate_chain *cert_chain,
                             psa_key_id_t *last_pub_key_id)
{
    int i, err;
    QCBORError qcbor_err;
    QCBORDecodeContext decode_ctx;
    UsefulOutBuf_MakeOnStack(pub_key_buf, DPE_ATTEST_PUB_KEY_SIZE);
    UsefulBufC pub_key, cert_buf;
    QCBORItem item;
    psa_status_t psa_err;
    psa_key_id_t pub_key_id;

    memset(cert_chain, 0, sizeof(struct certificate_chain));

    QCBORDecode_Init(&decode_ctx, cert_chain_buf, QCBOR_DECODE_MODE_NORMAL);

    /* Enter top level array and get the length of the chain */
    QCBORDecode_EnterArray(&decode_ctx, &item);
    qcbor_err = get_array_len(&item, &cert_chain->cert_cnt);
    if (qcbor_err != QCBOR_SUCCESS) {
        return -1;
    }

    /* Root public key: COSE_Key */
    QCBORDecode_GetByteString(&decode_ctx, &cert_chain->root_pub_key);

    /* Decode the COSE_Key and extract the public key */
    qcbor_err = get_public_key(cert_chain->root_pub_key, &pub_key_buf, &pub_key);
    if (qcbor_err != QCBOR_SUCCESS) {
        return -1;
    }

    /* The first item in the chain is the root public key and not a certificate */
    cert_chain->cert_cnt--;

    psa_err = register_pub_key(pub_key, &pub_key_id);
    if (psa_err != PSA_SUCCESS) {
        return -3;
    }

    if (cert_chain->cert_cnt == 0) {
        /* There is no certificate in the chain */
        return -1;
    }

    for (i = 0; i < cert_chain->cert_cnt ; ++i) {
        qcbor_err = get_next_certificate(&decode_ctx, &cert_buf);
        if (qcbor_err != QCBOR_SUCCESS) {
            return -1;
        }

        err = verify_certificate(cert_buf, pub_key_id, &cert_chain->cert_arr[i]);
        if (err != 0) {
            return err;
        }

        /* Decode the COSE_Key and extract the public key */
        qcbor_err = get_public_key(cert_chain->cert_arr[i].pub_key,
                                   &pub_key_buf,
                                   &pub_key);
        if (qcbor_err != QCBOR_SUCCESS) {
            return -1;
        }

        /* Set the key to verify the next certificate in the chain */
        psa_err = update_public_key(pub_key, &pub_key_id);
        if (psa_err != PSA_SUCCESS) {
            return -3;
        }
    }

    /* The last pub_key might not used for verification */
    if (last_pub_key_id == NULL) {
        psa_err = unregister_pub_key(pub_key_id);
        if (psa_err != PSA_SUCCESS) {
            return -3;
        }
    } else {
        *last_pub_key_id = pub_key_id;
    }

    QCBORDecode_ExitArray(&decode_ctx);

    qcbor_err = QCBORDecode_Finish(&decode_ctx);
    if (qcbor_err != QCBOR_SUCCESS) {
        return -1;
    }

#ifdef PRINT_CERT_CHAIN
    print_certificate_chain(cert_chain);
#endif

    return 0;
}
