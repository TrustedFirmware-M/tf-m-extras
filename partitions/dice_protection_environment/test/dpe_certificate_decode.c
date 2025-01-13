/*
 * Copyright (c) 2024-2025, Arm Limited. All rights reserved.
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
#include "t_cose/t_cose_common.h"
#include "t_cose/t_cose_key.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "test_log.h"

/* Uncomment this define to print the certificate chain */
//#define PRINT_CERT_CHAIN

#define COSE_SIGN1_ARRAY_LEN    4

static QCBORError get_array_len(QCBORItem *item, unsigned int *array_len)
{
    if (item->uDataType != QCBOR_TYPE_ARRAY) {
        return QCBOR_ERR_UNEXPECTED_TYPE;
    }

    *array_len = item->val.uCount;

    return QCBOR_SUCCESS;
}


static QCBORError get_next_certificate(QCBORDecodeContext *decode_ctx,
                                       UsefulBufC *cert_buf)
{
    QCBORError qcbor_err;
    QCBORItem item;
    unsigned int array_len;
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
    unsigned int array_len;

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
                                          struct t_cose_key pub_key_id)
{
    enum t_cose_err_t cose_err;
    struct t_cose_sign1_verify_ctx verify_ctx;
    UsefulBufC payload;

    t_cose_sign1_verify_init(&verify_ctx, 0); /* T_COSE_OPT_DECODE_ONLY */

    t_cose_sign1_set_verification_key(&verify_ctx, pub_key_id);
    cose_err =  t_cose_sign1_verify(&verify_ctx,
                                    cert_buf, /* COSE_Sign1 to verify */
                                    &payload,
                                    NULL);    /* Don't return parameters */

    return cose_err;
}

/*
 * Returns:
 *  - SUCCESS      :  0
 *  - QCBOR_ERR_*  : -1
 *  - T_COSE_ERR_* : -2
 */
int verify_certificate(UsefulBufC cert_buf,
                       struct t_cose_key pub_key_id,
                       struct certificate *cert)
{
    enum t_cose_err_t cose_err;
    QCBORError qcbor_err;

    qcbor_err = verify_encoding(cert_buf, cert);
    if (qcbor_err != QCBOR_SUCCESS) {
        return -1;
    }

    /* If the corresponding public key is not known then only verify the
     * certificate's structure.
     */
    if (pub_key_id.key.handle != PSA_KEY_ID_NULL ) {
        cose_err = verify_signature(cert_buf, pub_key_id);
        if (cose_err != T_COSE_SUCCESS) {
            return -2;
        }
    }

    return 0;
}

/* TODO: The t_cose lib has no API for this purpose use the PSA API instead */
inline int unregister_pub_key(struct t_cose_key pub_key_id)
{
    psa_status_t psa_err;

    psa_err = psa_destroy_key(pub_key_id.key.handle);
    if (psa_err != PSA_SUCCESS) {
        return -3;
    }

    return 0;
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
                             struct t_cose_key *last_pub_key_id)
{
    int i, err;
    QCBORError qcbor_err;
    QCBORDecodeContext decode_ctx;
    UsefulBufC cert_buf;
    QCBORItem item;
    psa_status_t psa_err;
    struct t_cose_key pub_key_id;
    enum t_cose_err_t cose_err;

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

    /* The first item in the chain is the root public key and not a certificate */
    cert_chain->cert_cnt--;

    /* Decode the COSE_Key and register the public key to the crypto backend */
    pub_key_id.key.handle = PSA_KEY_ID_NULL;
    cose_err = t_cose_key_decode(cert_chain->root_pub_key, &pub_key_id);
    if (cose_err != T_COSE_SUCCESS) {
        return -2;
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

        /* Remove the previous key from the crypto backend */
        err = unregister_pub_key(pub_key_id);
        if (err != 0) {
            return -3;
        }

        /* Decode the COSE_Key and register the public key to the crypto backend */
        cose_err = t_cose_key_decode(cert_chain->cert_arr[i].pub_key, &pub_key_id);
        if (cose_err != T_COSE_SUCCESS) {
            return -2;
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

int compare_certificate_chains(struct certificate_chain *decoded_chain_1,
                               struct certificate_chain *decoded_chain_2)
{
    int i, j;
    struct certificate *chain_1_cert, *chain_2_cert;
    struct component *chain_1_comp, *chain_2_comp;

    if (decoded_chain_1->cert_cnt != decoded_chain_2->cert_cnt) {
        TEST_LOG("Certificate chains diverge: Certificate count does not match");
        return -1;
    }

    if (memcmp(decoded_chain_1->root_pub_key.ptr,
               decoded_chain_2->root_pub_key.ptr,
               decoded_chain_1->root_pub_key.len)) {
        TEST_LOG("Certificate chains diverge: Root public key does not match");
        return -1;
    }

    for (i = 0; i < decoded_chain_1->cert_cnt; i++) {

        chain_1_cert = &decoded_chain_1->cert_arr[i];
        chain_2_cert = &decoded_chain_2->cert_arr[i];

        if (memcmp(chain_1_cert->protected_header.ptr,
                   chain_2_cert->protected_header.ptr,
                   chain_1_cert->protected_header.len)) {
            TEST_LOG("Certificate chains diverge: Protected header does not match");
            return -1;
        }

        if (memcmp(chain_1_cert->pub_key.ptr,
                   chain_2_cert->pub_key.ptr,
                   chain_1_cert->pub_key.len)) {
            TEST_LOG("Certificate chains diverge: Public key does not match");
            return -1;
        }

        if (memcmp(chain_1_cert->issuer.ptr,
                   chain_2_cert->issuer.ptr,
                   chain_1_cert->issuer.len)) {
            TEST_LOG("Certificate chains diverge: Issuer does not match");
            return -1;
        }

        if (memcmp(chain_1_cert->subject.ptr,
                   chain_2_cert->subject.ptr,
                   chain_1_cert->subject.len)) {
            TEST_LOG("Certificate chains diverge: Subject does not match");
            return -1;
        }

        if (memcmp(chain_1_cert->key_usage.ptr,
                   chain_2_cert->key_usage.ptr,
                   chain_1_cert->key_usage.len)) {
            TEST_LOG("Certificate chains diverge: Key usage does not match");
            return -1;
        }

        if (memcmp(chain_1_cert->external_label.ptr,
                   chain_2_cert->external_label.ptr,
                   chain_1_cert->external_label.len)) {
            TEST_LOG("Certificate chains diverge: External label does not match");
            return -1;
        }

        if ((chain_1_cert->cdi_export.presence) &&
            (chain_1_cert->cdi_export.value != chain_2_cert->cdi_export.value)) {
            TEST_LOG("Certificate chains diverge: Export CDI value does not match");
            return -1;
        }

        if (chain_1_cert->component_cnt != chain_2_cert->component_cnt) {
            TEST_LOG("Certificate chains diverge: Component count does not match");
            return -1;
        }

        for (j = 0; j < chain_1_cert->component_cnt; j++) {

            chain_1_comp = &chain_1_cert->component_arr[j];
            chain_2_comp = &chain_2_cert->component_arr[j];

            if (memcmp(chain_1_comp->code_hash.ptr,
                       chain_2_comp->code_hash.ptr,
                       chain_1_comp->code_hash.len)) {
                TEST_LOG("Certificate chains diverge: Component code hash does not match");
                return -1;
            }

            if (memcmp(chain_1_comp->authority_hash.ptr,
                       chain_2_comp->authority_hash.ptr,
                       chain_1_comp->authority_hash.len)) {
                TEST_LOG("Certificate chains diverge: Component authority hash does not match");
                return -1;
            }

            if (memcmp(chain_1_comp->code_descriptor.ptr,
                       chain_2_comp->code_descriptor.ptr,
                       chain_1_comp->code_descriptor.len)) {
                TEST_LOG("Certificate chains diverge: Component descriptor does not match");
                return -1;
            }

            //TODO: Add remaining checks except signature when remaining elements
            //      are added to struct component type
        }
    }

    return 0;
}

/* This is a simpler version of the previous function which only compares a
 * subset of the certificate elements. It is meant to verify that a certificate
 * chain does include the expected components but nothing else. The order of
 * the components within the certificate does matter.
 */
int compare_certificate_chains_light(struct certificate_chain *decoded_chain_1,
                                     struct certificate_chain *decoded_chain_2)
{
    int i, j;
    struct certificate *chain_1_cert, *chain_2_cert;
    struct component *chain_1_comp, *chain_2_comp;

    if (decoded_chain_1->cert_cnt != decoded_chain_2->cert_cnt) {
        TEST_LOG("Certificate chains diverge: Certificate count does not match");
        return -1;
    }

    for (i = 0; i < decoded_chain_1->cert_cnt; i++) {

        chain_1_cert = &decoded_chain_1->cert_arr[i];
        chain_2_cert = &decoded_chain_2->cert_arr[i];

        if (chain_1_cert->component_cnt != chain_2_cert->component_cnt) {
            TEST_LOG("Certificate chains diverge: Component count does not match");
            return -1;
        }

        for (j = 0; j < chain_1_cert->component_cnt; j++) {

            chain_1_comp = &chain_1_cert->component_arr[j];
            chain_2_comp = &chain_2_cert->component_arr[j];

            if (memcmp(chain_1_comp->code_hash.ptr,
                       chain_2_comp->code_hash.ptr,
                       chain_1_comp->code_hash.len)) {
                TEST_LOG("Certificate chains diverge: Component code hash does not match");
                return -1;
            }

            if (memcmp(chain_1_comp->authority_hash.ptr,
                       chain_2_comp->authority_hash.ptr,
                       chain_1_comp->authority_hash.len)) {
                TEST_LOG("Certificate chains diverge: Component authority hash does not match");
                return -1;
            }

            //TODO: Add remaining checks except signature when remaining elements
            //      are added to struct component type
        }
    }

    return 0;
}
