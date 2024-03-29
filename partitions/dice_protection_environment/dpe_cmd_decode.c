/*
 * Copyright (c) 2023-2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dpe_cmd_decode.h"

#include <string.h>

#include "dpe_client.h"
#include "dpe_context_mngr.h"
#include "dpe_crypto_config.h"
#include "qcbor/qcbor_encode.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"

#define CHECK_CBOR_ERROR(decode_ctx)                                                \
    qcbor_err = QCBORDecode_GetAndResetError(decode_ctx);                           \
    if ((qcbor_err != QCBOR_SUCCESS) && (qcbor_err != QCBOR_ERR_LABEL_NOT_FOUND)) { \
        return DPE_INVALID_COMMAND;                                                 \
    }

/*
 * The goal to reuse the cmd_buf allocated in dpe_req_mngr.c to create the
 * big objects (certificate, certificate_chain) in place rather then allocate
 * a separate  buffer on the stack and later copy them to cmd_buf.
 *
 * The temporary buffer is allocated from the end of the cmd_buf. When the
 * reply is encoded then the content of the temp buf is moved to its final
 * place in the cmd_buf.
 *
 * Overlapping copy is not an issue because QCBOR relies on memmove under the
 * hood which handles this scenario.
 *
 * Note:
 *   Make sure that the beginning of the encoded reply does not overwrite the
 *   data in the temp buf. That is why the temp buff is allocated at the end of
 *   cmd_buf.
 */
#define REUSE_CMD_BUF(size)  (uint8_t *)encode_ctx->OutBuf.UB.ptr + \
                                        encode_ctx->OutBuf.UB.len - \
                                        (size)

static dpe_error_t decode_dice_inputs(QCBORDecodeContext *decode_ctx,
                                      DiceInputValues *input)
{
    QCBORError qcbor_err;
    UsefulBufC out = { NULL, 0 };
    int64_t out_int;

    /* The DICE inputs are encoded as a map wrapped into a byte string */
    QCBORDecode_EnterBstrWrappedFromMapN(decode_ctx,
                                         DPE_DERIVE_CONTEXT_INPUT_DATA,
                                         QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
    QCBORDecode_EnterMap(decode_ctx, NULL);

    QCBORDecode_GetByteStringInMapN(decode_ctx, DICE_CODE_HASH, &out);
    if (out.len != sizeof(input->code_hash)) {
        return DPE_INVALID_COMMAND;
    }
    memcpy(input->code_hash, out.ptr, out.len);

    QCBORDecode_GetByteStringInMapN(decode_ctx, DICE_CODE_DESCRIPTOR, &out);
    input->code_descriptor = out.ptr;
    input->code_descriptor_size = out.len;

    QCBORDecode_GetInt64InMapN(decode_ctx, DICE_CONFIG_TYPE, &out_int);

    /* Check error state before interpreting config type */
    qcbor_err = QCBORDecode_GetError(decode_ctx);
    if (qcbor_err != QCBOR_SUCCESS) {
        return DPE_INVALID_COMMAND;
    }

    if (out_int < kDiceConfigTypeInline ||
        out_int > kDiceConfigTypeDescriptor) {
        return DPE_INVALID_COMMAND;
    }
    input->config_type = (DiceConfigType)out_int;

    /* Only one of config value or config descriptor needs to be provided */
    if (input->config_type == kDiceConfigTypeInline) {
        QCBORDecode_GetByteStringInMapN(decode_ctx, DICE_CONFIG_VALUE, &out);
        if (out.len != sizeof(input->config_value)) {
            return DPE_INVALID_COMMAND;
        }
        memcpy(input->config_value, out.ptr, out.len);

        /* Config descriptor is not provided */
        input->config_descriptor = NULL;
        input->config_descriptor_size = 0;
    } else {
        QCBORDecode_GetByteStringInMapN(decode_ctx, DICE_CONFIG_DESCRIPTOR,
                                        &out);
        input->config_descriptor = out.ptr;
        input->config_descriptor_size = out.len;

        /* Config value is not provided */
        memset(input->config_value, 0, sizeof(input->config_value));
    }

    QCBORDecode_GetByteStringInMapN(decode_ctx, DICE_AUTHORITY_HASH, &out);
    if (out.len != sizeof(input->authority_hash)) {
        return DPE_INVALID_COMMAND;
    }
    memcpy(input->authority_hash, out.ptr, out.len);

    QCBORDecode_GetByteStringInMapN(decode_ctx, DICE_AUTHORITY_DESCRIPTOR,
                                    &out);
    input->authority_descriptor = out.ptr;
    input->authority_descriptor_size = out.len;

    QCBORDecode_GetInt64InMapN(decode_ctx, DICE_MODE, &out_int);
    if (out_int < kDiceModeNotInitialized || out_int > kDiceModeMaintenance) {
        return DPE_INVALID_COMMAND;
    }
    input->mode = (DiceMode)out_int;

    QCBORDecode_GetByteStringInMapN(decode_ctx, DICE_HIDDEN, &out);
    if (out.len != sizeof(input->hidden)) {
        return DPE_INVALID_COMMAND;
    }
    memcpy(input->hidden, out.ptr, out.len);

    QCBORDecode_ExitMap(decode_ctx);
    QCBORDecode_ExitBstrWrapped(decode_ctx);

    qcbor_err = QCBORDecode_GetError(decode_ctx);
    if (qcbor_err != QCBOR_SUCCESS) {
        return DPE_INVALID_COMMAND;
    }

    return DPE_NO_ERROR;
}

static dpe_error_t decode_derive_context(QCBORDecodeContext *decode_ctx,
                                         QCBOREncodeContext *encode_ctx,
                                         int32_t client_id)
{
    dpe_error_t dpe_err;
    QCBORError qcbor_err;
    UsefulBufC out;
    int context_handle;
    int32_t target_locality;
    bool retain_parent_context;
    bool allow_new_context_to_derive;
    bool create_certificate;
    bool return_certificate;
    bool allow_new_context_to_export;
    bool export_cdi;
    DiceInputValues dice_inputs;
    int new_context_handle;
    int new_parent_context_handle;
    uint8_t *new_certificate_buf = REUSE_CMD_BUF(DICE_CERT_SIZE);
    uint8_t exported_cdi_buf[DICE_MAX_ENCODED_CDI_SIZE];
    uint32_t cert_id;
    size_t new_certificate_actual_size = 0;
    size_t exported_cdi_actual_size = 0;

    /* Initialise optional parameters with their default value in case
     * they are not encoded in the input command
     */
    cert_id = DPE_CERT_ID_INVALID;
    retain_parent_context = false;
    allow_new_context_to_derive = true;
    create_certificate = true;
    return_certificate = false;
    allow_new_context_to_export = false;
    export_cdi = false;

    /* Decode DeriveContext command */
    QCBORDecode_EnterMap(decode_ctx, NULL);

    QCBORDecode_GetByteStringInMapN(decode_ctx, DPE_DERIVE_CONTEXT_CONTEXT_HANDLE,
                                    &out);
    qcbor_err = QCBORDecode_GetAndResetError(decode_ctx);
    if ((qcbor_err != QCBOR_SUCCESS) || (out.len != sizeof(context_handle))) {
        return DPE_INVALID_COMMAND;
    }
    memcpy(&context_handle, out.ptr, out.len);

    QCBORDecode_GetUInt64InMapN(decode_ctx, DPE_DERIVE_CONTEXT_CERT_ID, &cert_id);
    /* Check if cert_id was encoded in the received command buffer */
    CHECK_CBOR_ERROR(decode_ctx);

    QCBORDecode_GetBoolInMapN(decode_ctx, DPE_DERIVE_CONTEXT_RETAIN_PARENT_CONTEXT,
                              &retain_parent_context);
    CHECK_CBOR_ERROR(decode_ctx);

    QCBORDecode_GetBoolInMapN(decode_ctx, DPE_DERIVE_CONTEXT_ALLOW_NEW_CONTEXT_TO_DERIVE,
                              &allow_new_context_to_derive);
    CHECK_CBOR_ERROR(decode_ctx);

    QCBORDecode_GetBoolInMapN(decode_ctx, DPE_DERIVE_CONTEXT_CREATE_CERTIFICATE,
                              &create_certificate);
    CHECK_CBOR_ERROR(decode_ctx);

    dpe_err = decode_dice_inputs(decode_ctx, &dice_inputs);
    if (dpe_err != DPE_NO_ERROR) {
        return dpe_err;
    }

    QCBORDecode_GetByteStringInMapN(decode_ctx, DPE_DERIVE_CONTEXT_TARGET_LOCALITY,
                                    &out);
    if (out.len != sizeof(target_locality)) {
        return DPE_INVALID_COMMAND;
    }
    memcpy(&target_locality, out.ptr, out.len);

    QCBORDecode_GetBoolInMapN(decode_ctx, DPE_DERIVE_CONTEXT_RETURN_CERTIFICATE,
                              &return_certificate);
    CHECK_CBOR_ERROR(decode_ctx);

    QCBORDecode_GetBoolInMapN(decode_ctx, DPE_DERIVE_CONTEXT_ALLOW_NEW_CONTEXT_TO_EXPORT,
                              &allow_new_context_to_export);
    CHECK_CBOR_ERROR(decode_ctx);

    QCBORDecode_GetBoolInMapN(decode_ctx, DPE_DERIVE_CONTEXT_EXPORT_CDI,
                              &export_cdi);
    CHECK_CBOR_ERROR(decode_ctx);

    QCBORDecode_ExitMap(decode_ctx);

    /* Exit top level array */
    QCBORDecode_ExitArray(decode_ctx);

    /* Finish and check for errors before using decoded values */
    qcbor_err = QCBORDecode_Finish(decode_ctx);
    if (qcbor_err != QCBOR_SUCCESS) {
        return DPE_INVALID_COMMAND;
    }

    dpe_err = derive_context_request(context_handle, cert_id, retain_parent_context,
                                     allow_new_context_to_derive, create_certificate,
                                     &dice_inputs, client_id,
                                     target_locality,
                                     return_certificate,
                                     allow_new_context_to_export,
                                     export_cdi,
                                     &new_context_handle,
                                     &new_parent_context_handle,
                                     new_certificate_buf,
                                     DICE_CERT_SIZE,
                                     &new_certificate_actual_size,
                                     exported_cdi_buf,
                                     sizeof(exported_cdi_buf),
                                     &exported_cdi_actual_size);
    if (dpe_err != DPE_NO_ERROR) {
        return dpe_err;
    }

    /* Encode response */
    QCBOREncode_OpenArray(encode_ctx);
    QCBOREncode_AddInt64(encode_ctx, DPE_NO_ERROR);

    QCBOREncode_OpenMap(encode_ctx);
    QCBOREncode_AddBytesToMapN(encode_ctx, DPE_DERIVE_CONTEXT_NEW_CONTEXT_HANDLE,
                               (UsefulBufC){ &new_context_handle,
                                             sizeof(new_context_handle) });
    QCBOREncode_AddBytesToMapN(encode_ctx,
                               DPE_DERIVE_CONTEXT_PARENT_CONTEXT_HANDLE,
                               (UsefulBufC){ &new_parent_context_handle,
                                             sizeof(new_parent_context_handle) });

    /* The certificate is already encoded into a CBOR array by the function
     * add_encoded_layer_certificate. Add it as a byte string so that its
     * decoding can be skipped and the CBOR returned to the caller.
     */
    QCBOREncode_AddBytesToMapN(encode_ctx, DPE_DERIVE_CONTEXT_NEW_CERTIFICATE,
                               (UsefulBufC){ new_certificate_buf,
                                             new_certificate_actual_size });

    QCBOREncode_AddBytesToMapN(encode_ctx, DPE_DERIVE_CONTEXT_EXPORTED_CDI,
                               (UsefulBufC){ exported_cdi_buf,
                                             exported_cdi_actual_size });

    QCBOREncode_CloseMap(encode_ctx);

    QCBOREncode_CloseArray(encode_ctx);

    return DPE_NO_ERROR;
}

static dpe_error_t decode_destroy_context(QCBORDecodeContext *decode_ctx,
                                          QCBOREncodeContext *encode_ctx)
{
    dpe_error_t dpe_err;
    QCBORError qcbor_err;
    UsefulBufC out;
    int context_handle;
    bool destroy_recursively;

    /* Decode Destroy context command */
    QCBORDecode_EnterMap(decode_ctx, NULL);

    QCBORDecode_GetByteStringInMapN(decode_ctx, DPE_DESTROY_CONTEXT_HANDLE,
                                    &out);
    if (out.len != sizeof(context_handle)) {
        return DPE_INVALID_COMMAND;
    }
    memcpy(&context_handle, out.ptr, out.len);

    QCBORDecode_GetBoolInMapN(decode_ctx, DPE_DESTROY_CONTEXT_RECURSIVELY,
                              &destroy_recursively);

    QCBORDecode_ExitMap(decode_ctx);

    /* Exit top level array */
    QCBORDecode_ExitArray(decode_ctx);

    /* Finish and check for errors before using decoded values */
    qcbor_err = QCBORDecode_Finish(decode_ctx);
    if (qcbor_err != QCBOR_SUCCESS) {
        return DPE_INVALID_COMMAND;
    }

    dpe_err = destroy_context_request(context_handle, destroy_recursively);
    if (dpe_err != DPE_NO_ERROR) {
        return dpe_err;
    }

    /* Encode response */
    QCBOREncode_OpenArray(encode_ctx);
    QCBOREncode_AddInt64(encode_ctx, DPE_NO_ERROR);
    QCBOREncode_CloseArray(encode_ctx);

    return DPE_NO_ERROR;
}

static dpe_error_t decode_certify_key(QCBORDecodeContext *decode_ctx,
                                      QCBOREncodeContext *encode_ctx)
{
    QCBORError qcbor_err;
    UsefulBufC out;
    dpe_error_t dpe_err;
    int context_handle;
    bool retain_context;
    const uint8_t *public_key = NULL;
    size_t public_key_size;
    const uint8_t *label = NULL;
    size_t label_size;
    uint8_t *certificate_buf = REUSE_CMD_BUF(DICE_CERT_SIZE);
    size_t certificate_actual_size;
    uint8_t derived_public_key_buf[DPE_ATTEST_PUB_KEY_SIZE];
    size_t derived_public_key_actual_size;
    int new_context_handle;

    /* Initialise optional parameters with their default value in case
     * they are not encoded in the input command
     */
    retain_context = false;
    public_key_size = 0;
    label_size = 0;

    /* Decode CertifyKey command */
    QCBORDecode_EnterMap(decode_ctx, NULL);

    QCBORDecode_GetByteStringInMapN(decode_ctx, DPE_CERTIFY_KEY_CONTEXT_HANDLE,
                                    &out);
    qcbor_err = QCBORDecode_GetAndResetError(decode_ctx);
    if ((qcbor_err != QCBOR_SUCCESS) || (out.len != sizeof(context_handle))) {
        return DPE_INVALID_COMMAND;
    }
    memcpy(&context_handle, out.ptr, out.len);

    QCBORDecode_GetBoolInMapN(decode_ctx, DPE_CERTIFY_KEY_RETAIN_CONTEXT,
                              &retain_context);
    CHECK_CBOR_ERROR(decode_ctx);

    QCBORDecode_GetByteStringInMapN(decode_ctx, DPE_CERTIFY_KEY_PUBLIC_KEY,
                                    &out);
    qcbor_err = QCBORDecode_GetAndResetError(decode_ctx);
    if (qcbor_err == QCBOR_SUCCESS) {
        public_key = out.ptr;
        public_key_size = out.len;
    } else if (qcbor_err == QCBOR_ERR_LABEL_NOT_FOUND) {
        /* Do nothing - argument already initialised to default value */
    } else {
        return DPE_INVALID_COMMAND;
    }

    QCBORDecode_GetByteStringInMapN(decode_ctx, DPE_CERTIFY_KEY_LABEL, &out);
    qcbor_err = QCBORDecode_GetAndResetError(decode_ctx);
    if (qcbor_err == QCBOR_SUCCESS) {
        label = out.ptr;
        label_size = out.len;
    } else if (qcbor_err == QCBOR_ERR_LABEL_NOT_FOUND) {
        /* Do nothing - argument already initialised to default value */
    } else {
        return DPE_INVALID_COMMAND;
    }

    QCBORDecode_ExitMap(decode_ctx);

    /* Exit top level array */
    QCBORDecode_ExitArray(decode_ctx);

    /* Finish and check for errors before using decoded values */
    qcbor_err = QCBORDecode_Finish(decode_ctx);
    if (qcbor_err != QCBOR_SUCCESS) {
        return DPE_INVALID_COMMAND;
    }

    dpe_err = certify_key_request(context_handle, retain_context, public_key,
                                  public_key_size, label, label_size,
                                  certificate_buf,
                                  DICE_CERT_SIZE,
                                  &certificate_actual_size,
                                  derived_public_key_buf,
                                  sizeof(derived_public_key_buf),
                                  &derived_public_key_actual_size,
                                  &new_context_handle);
    if (dpe_err != DPE_NO_ERROR) {
        return dpe_err;
    }

    /* Encode response */
    QCBOREncode_OpenArray(encode_ctx);
    QCBOREncode_AddInt64(encode_ctx, DPE_NO_ERROR);

    QCBOREncode_OpenMap(encode_ctx);

    /* The certificate chain is already encoded into a CBOR array by the certify
     * key implementation. Add it as a byte string so that its decoding can be
     * skipped and the CBOR returned to the caller.
     */
    QCBOREncode_AddBytesToMapN(encode_ctx, DPE_CERTIFY_KEY_CERTIFICATE,
                               (UsefulBufC){ certificate_buf,
                                             certificate_actual_size });

    QCBOREncode_AddBytesToMapN(encode_ctx, DPE_CERTIFY_KEY_DERIVED_PUBLIC_KEY,
                               (UsefulBufC){ derived_public_key_buf,
                                             derived_public_key_actual_size });
    QCBOREncode_AddBytesToMapN(encode_ctx, DPE_CERTIFY_KEY_NEW_CONTEXT_HANDLE,
                               (UsefulBufC){ &new_context_handle,
                                             sizeof(new_context_handle) });

    QCBOREncode_CloseMap(encode_ctx);

    QCBOREncode_CloseArray(encode_ctx);

    return DPE_NO_ERROR;
}

static dpe_error_t decode_get_certificate_chain(QCBORDecodeContext *decode_ctx,
                                                QCBOREncodeContext *encode_ctx)
{
    QCBORError qcbor_err;
    UsefulBufC out;
    dpe_error_t dpe_err;
    int context_handle;
    bool retain_context;
    bool clear_from_context;
    uint8_t *certificate_chain_buf = REUSE_CMD_BUF(DICE_CERT_CHAIN_SIZE);
    size_t certificate_chain_actual_size;
    int new_context_handle;

    /* Initialise optional parameters with their default value in case
     * they are not encoded in the input command
     */
    retain_context = false;
    clear_from_context = false;

    /* Decode GetCertificateChain command */
    QCBORDecode_EnterMap(decode_ctx, NULL);

    QCBORDecode_GetByteStringInMapN(decode_ctx, DPE_GET_CERTIFICATE_CHAIN_CONTEXT_HANDLE,
                                    &out);
    qcbor_err = QCBORDecode_GetAndResetError(decode_ctx);
    if ((qcbor_err != QCBOR_SUCCESS) || (out.len != sizeof(context_handle))) {
        return DPE_INVALID_COMMAND;
    }
    memcpy(&context_handle, out.ptr, out.len);

    QCBORDecode_GetBoolInMapN(decode_ctx, DPE_GET_CERTIFICATE_CHAIN_RETAIN_CONTEXT,
                              &retain_context);
    CHECK_CBOR_ERROR(decode_ctx);

    QCBORDecode_GetBoolInMapN(decode_ctx, DPE_GET_CERTIFICATE_CHAIN_CLEAR_FROM_CONTEXT,
                              &clear_from_context);
    CHECK_CBOR_ERROR(decode_ctx);

    QCBORDecode_ExitMap(decode_ctx);

    /* Exit top level array */
    QCBORDecode_ExitArray(decode_ctx);

    /* Finish and check for errors before using decoded values */
    qcbor_err = QCBORDecode_Finish(decode_ctx);
    if (qcbor_err != QCBOR_SUCCESS) {
        return DPE_INVALID_COMMAND;
    }

    dpe_err = get_certificate_chain_request(context_handle,
                                            retain_context,
                                            clear_from_context,
                                            certificate_chain_buf,
                                            DICE_CERT_CHAIN_SIZE,
                                            &certificate_chain_actual_size,
                                            &new_context_handle);
    if (dpe_err != DPE_NO_ERROR) {
        return dpe_err;
    }

    /* Encode response */
    QCBOREncode_OpenArray(encode_ctx);
    QCBOREncode_AddInt64(encode_ctx, DPE_NO_ERROR);

    QCBOREncode_OpenMap(encode_ctx);

    /* The certificate chain is already encoded into a CBOR array by the get certificate
     * chain implementation. Add it as a byte string so that its decoding can be
     * skipped and the CBOR returned to the caller.
     */
    QCBOREncode_AddBytesToMapN(encode_ctx, DPE_GET_CERTIFICATE_CHAIN_CERTIFICATE_CHAIN,
                               (UsefulBufC){ certificate_chain_buf,
                                             certificate_chain_actual_size });

    QCBOREncode_AddBytesToMapN(encode_ctx, DPE_GET_CERTIFICATE_CHAIN_NEW_CONTEXT_HANDLE,
                               (UsefulBufC){ &new_context_handle,
                                             sizeof(new_context_handle) });

    QCBOREncode_CloseMap(encode_ctx);

    QCBOREncode_CloseArray(encode_ctx);

    return DPE_NO_ERROR;
}

static void encode_error_only(QCBOREncodeContext *encode_ctx,
                              dpe_error_t dpe_err)
{
    QCBOREncode_OpenArray(encode_ctx);
    QCBOREncode_AddInt64(encode_ctx, dpe_err);
    QCBOREncode_CloseArray(encode_ctx);
}

int32_t dpe_command_decode(int32_t client_id,
                           const char *cmd_input, size_t cmd_input_size,
                           char *cmd_output, size_t *cmd_output_size)
{
    dpe_error_t dpe_err;
    QCBORError qcbor_err;
    QCBORDecodeContext decode_ctx;
    QCBOREncodeContext encode_ctx;
    UsefulBufC out;
    uint64_t command_id;

    QCBORDecode_Init(&decode_ctx, (UsefulBufC){ cmd_input, cmd_input_size },
                     QCBOR_DECODE_MODE_NORMAL);
    QCBOREncode_Init(&encode_ctx, (UsefulBuf){ cmd_output, *cmd_output_size });

    /* Enter top level array */
    QCBORDecode_EnterArray(&decode_ctx, NULL);

    /* Get the command ID */
    QCBORDecode_GetUInt64(&decode_ctx, &command_id);

    /* Check for errors before interpreting the decoded command ID */
    qcbor_err = QCBORDecode_GetError(&decode_ctx);

    if (qcbor_err == QCBOR_SUCCESS) {
        switch (command_id) {
        case DPE_DERIVE_CONTEXT:
            dpe_err = decode_derive_context(&decode_ctx, &encode_ctx, client_id);
            break;
        case DPE_CERTIFY_KEY:
            dpe_err = decode_certify_key(&decode_ctx, &encode_ctx);
            break;
        case DPE_GET_CERTIFICATE_CHAIN:
            dpe_err = decode_get_certificate_chain(&decode_ctx, &encode_ctx);
            break;
        case DPE_DESTROY_CONTEXT:
            dpe_err = decode_destroy_context(&decode_ctx, &encode_ctx);
            break;
        default:
            dpe_err = DPE_INVALID_COMMAND;
            break;
        }
    } else {
        dpe_err = DPE_INVALID_COMMAND;
    }

    /* If an unhandled DPE error was returned, then encode it into a response */
    if (dpe_err != DPE_NO_ERROR) {
        encode_error_only(&encode_ctx, dpe_err);
    }

    qcbor_err = QCBOREncode_Finish(&encode_ctx, &out);
    if (qcbor_err != QCBOR_SUCCESS) {
        return -1;
    }

    *cmd_output_size = out.len;

    return 0;
}
