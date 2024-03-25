/*
 * Copyright (c) 2023-2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dpe_cmd_decode.h"

#include <assert.h>
#include <string.h>

#include "dpe_client.h"
#include "dpe_context_mngr.h"
#include "dpe_crypto_config.h"
#include "qcbor/qcbor_encode.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"

/*
 * The goal to reuse the cmd_buf allocated in dpe_req_mngr.c to create the
 * big objects (certificate, certificate_chain) in place rather then allocate
 * a separate buffer on the stack and later copy them to cmd_buf.
 *
 * The temporary buffer is allocated from the beginning + some offset of the
 * cmd_buf. The offset is a placeholder for the first few bytes of the
 * response. The size of temp buf is till the end of the cmd_buf. Usually not
 * the entire size is necessary it is just convenient to allocate as much. When
 * the response is encoded then the content of the temp buf is moved to its
 * final location within the cmd_buf.
 *
 * Overlapping copy is not an issue because QCBOR relies on memmove under the
 * hood which handles this scenario.
 *
 * Note:
 *   Only a single temp buffer can be allocated with this trick per DPE command.
 */
#define DPE_RESPONSE_HEADER_SIZE  20
#define ALLOC_TEMP_BUF      (uint8_t *)encode_ctx->OutBuf.UB.ptr + \
                                       DPE_RESPONSE_HEADER_SIZE

#define SIZEOF_TEMP_BUF     encode_ctx->OutBuf.UB.len - \
                                       DPE_RESPONSE_HEADER_SIZE

/* Decreasing the placeholder size a bit because UsefulOutBuf_GetEndPosition()
 * cannot determine the exact number of bytes to encode array and map objects
 * until they are closed. Allocating 1 byte for both allows encoding up to
 * 23 elements per type (map or array) in a single byte, so at the end it
 * consumes 2 bytes. It is very unlikely to have more elements in a map or array
 * than 23 in a DPE response.
 */
#define CHECK_OVERFLOW_TO_TEMP_BUF assert((DPE_RESPONSE_HEADER_SIZE - 2) > \
                        UsefulOutBuf_GetEndPosition(&encode_ctx->OutBuf))

#define COUNT_ARGS(arg)  (arg)++

#define CHECK_AND_COUNT_OPTIONAL_ARGUMENT(decode_ctx)                          \
    qcbor_err = QCBORDecode_GetAndResetError(decode_ctx);                      \
    if (qcbor_err == QCBOR_SUCCESS) {                                          \
        /* Valid label found - optional argument present */                    \
        COUNT_ARGS(num_of_valid_arguments);                                    \
    } else if (qcbor_err != QCBOR_ERR_LABEL_NOT_FOUND) {                       \
        return DPE_INVALID_ARGUMENT;                                           \
    } else {                                                                   \
        /* We have NOT found the optional argument, do not update the count */ \
    }

static dpe_error_t decode_dice_inputs(QCBORDecodeContext *decode_ctx,
                                      DiceInputValues *input)
{
    QCBORError qcbor_err;
    UsefulBufC out = { NULL, 0 };
    int64_t out_int;
    uint16_t num_of_input_arguments, num_of_valid_arguments = 0;
    QCBORItem item;

    /* The DICE inputs are encoded as a map wrapped into a byte string */
    QCBORDecode_EnterBstrWrappedFromMapN(decode_ctx,
                                         DPE_DERIVE_CONTEXT_INPUT_DATA,
                                         QCBOR_TAG_REQUIREMENT_NOT_A_TAG, NULL);
    QCBORDecode_EnterMap(decode_ctx, &item);
    qcbor_err = QCBORDecode_GetError(decode_ctx);
    if ((qcbor_err != QCBOR_SUCCESS) ||
        (item.uDataType != QCBOR_TYPE_MAP)) {
            /* We expect a map of Dice inputs here */
            return DPE_INVALID_ARGUMENT;
    }
    /* Save the number of items found in the map */
    num_of_input_arguments = item.val.uCount;

    QCBORDecode_GetByteStringInMapN(decode_ctx, DICE_CODE_HASH, &out);
    qcbor_err = QCBORDecode_GetError(decode_ctx);
    if ((qcbor_err != QCBOR_SUCCESS) || (out.len != sizeof(input->code_hash))) {
        return DPE_INVALID_ARGUMENT;
    }
    memcpy(input->code_hash, out.ptr, out.len);
    COUNT_ARGS(num_of_valid_arguments);

    QCBORDecode_GetByteStringInMapN(decode_ctx, DICE_CODE_DESCRIPTOR, &out);
    CHECK_AND_COUNT_OPTIONAL_ARGUMENT(decode_ctx);
    if (qcbor_err == QCBOR_SUCCESS) {
        /* Valid argument was found */
        input->code_descriptor = out.ptr;
        input->code_descriptor_size = out.len;
    }

    QCBORDecode_GetInt64InMapN(decode_ctx, DICE_CONFIG_TYPE, &out_int);

    /* Check error state before interpreting config type */
    qcbor_err = QCBORDecode_GetError(decode_ctx);
    if (qcbor_err != QCBOR_SUCCESS) {
        return DPE_INVALID_ARGUMENT;
    }

    if (out_int < kDiceConfigTypeInline ||
        out_int > kDiceConfigTypeDescriptor) {
        return DPE_INVALID_ARGUMENT;
    }
    COUNT_ARGS(num_of_valid_arguments);
    input->config_type = (DiceConfigType)out_int;

    /* Only one of config value or config descriptor needs to be provided */
    if (input->config_type == kDiceConfigTypeInline) {
        QCBORDecode_GetByteStringInMapN(decode_ctx, DICE_CONFIG_VALUE, &out);
        qcbor_err = QCBORDecode_GetError(decode_ctx);
        if ((qcbor_err != QCBOR_SUCCESS) || (out.len != sizeof(input->config_value))) {
            return DPE_INVALID_ARGUMENT;
        }
        COUNT_ARGS(num_of_valid_arguments);
        memcpy(input->config_value, out.ptr, out.len);

        /* Config descriptor is not provided */
        input->config_descriptor = NULL;
        input->config_descriptor_size = 0;
    } else {
        QCBORDecode_GetByteStringInMapN(decode_ctx, DICE_CONFIG_DESCRIPTOR,
                                        &out);
        qcbor_err = QCBORDecode_GetError(decode_ctx);
        if (qcbor_err != QCBOR_SUCCESS) {
            return DPE_INVALID_ARGUMENT;
        }
        COUNT_ARGS(num_of_valid_arguments);
        input->config_descriptor = out.ptr;
        input->config_descriptor_size = out.len;

        /* Config value is not provided */
        memset(input->config_value, 0, sizeof(input->config_value));
    }

    QCBORDecode_GetByteStringInMapN(decode_ctx, DICE_AUTHORITY_HASH, &out);
    qcbor_err = QCBORDecode_GetError(decode_ctx);
    if ((qcbor_err != QCBOR_SUCCESS) || (out.len != sizeof(input->authority_hash))) {
        return DPE_INVALID_ARGUMENT;
    }
    COUNT_ARGS(num_of_valid_arguments);
    memcpy(input->authority_hash, out.ptr, out.len);

    QCBORDecode_GetByteStringInMapN(decode_ctx, DICE_AUTHORITY_DESCRIPTOR,
                                    &out);
    CHECK_AND_COUNT_OPTIONAL_ARGUMENT(decode_ctx);
    if (qcbor_err == QCBOR_SUCCESS) {
        /* Valid argument was found */
        input->authority_descriptor = out.ptr;
        input->authority_descriptor_size = out.len;
    }

    QCBORDecode_GetInt64InMapN(decode_ctx, DICE_MODE, &out_int);
    if (out_int < kDiceModeNotInitialized || out_int > kDiceModeMaintenance) {
        return DPE_INVALID_ARGUMENT;
    }
    COUNT_ARGS(num_of_valid_arguments);
    input->mode = (DiceMode)out_int;

    QCBORDecode_GetByteStringInMapN(decode_ctx, DICE_HIDDEN, &out);
    if (out.len != sizeof(input->hidden)) {
        return DPE_INVALID_ARGUMENT;
    }
    COUNT_ARGS(num_of_valid_arguments);
    memcpy(input->hidden, out.ptr, out.len);

    QCBORDecode_ExitMap(decode_ctx);
    QCBORDecode_ExitBstrWrapped(decode_ctx);

    qcbor_err = QCBORDecode_GetError(decode_ctx);
    if (qcbor_err != QCBOR_SUCCESS) {
        return DPE_INVALID_ARGUMENT;
    }

    if (num_of_input_arguments > num_of_valid_arguments) {
        /* Extra unsupported arguments encoded in command map */
        return DPE_INVALID_ARGUMENT;
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
    DiceInputValues dice_inputs = {0};
    int new_context_handle;
    int new_parent_context_handle;
    uint8_t *new_certificate_buf = ALLOC_TEMP_BUF;
    uint8_t exported_cdi_buf[DICE_MAX_ENCODED_CDI_SIZE];
    uint32_t cert_id;
    size_t new_certificate_actual_size = 0;
    size_t exported_cdi_actual_size = 0;
    QCBORItem item;
    uint16_t num_of_input_arguments, num_of_valid_arguments = 0;

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
    target_locality = DEFAULT_TARGET_LOCALITY;

    /* Decode DeriveContext command */
    QCBORDecode_EnterMap(decode_ctx, &item);
    qcbor_err = QCBORDecode_GetError(decode_ctx);
    if ((qcbor_err != QCBOR_SUCCESS) ||
        (item.uDataType != QCBOR_TYPE_MAP)) {
            /* We expect a map of Derive Context command arguments here */
            return DPE_INVALID_COMMAND;
    }
    /* Save the number of items found in the map */
    num_of_input_arguments = item.val.uCount;

    QCBORDecode_GetByteStringInMapN(decode_ctx, DPE_DERIVE_CONTEXT_CONTEXT_HANDLE,
                                    &out);
    qcbor_err = QCBORDecode_GetError(decode_ctx);
    if ((qcbor_err != QCBOR_SUCCESS) || (out.len != sizeof(context_handle))) {
        return DPE_INVALID_ARGUMENT;
    }
    memcpy(&context_handle, out.ptr, out.len);
    COUNT_ARGS(num_of_valid_arguments);

    QCBORDecode_GetUInt64InMapN(decode_ctx, DPE_DERIVE_CONTEXT_CERT_ID, &cert_id);
    /* Check if cert_id was encoded in the received command buffer */
    CHECK_AND_COUNT_OPTIONAL_ARGUMENT(decode_ctx);

    QCBORDecode_GetBoolInMapN(decode_ctx, DPE_DERIVE_CONTEXT_RETAIN_PARENT_CONTEXT,
                              &retain_parent_context);
    CHECK_AND_COUNT_OPTIONAL_ARGUMENT(decode_ctx);

    QCBORDecode_GetBoolInMapN(decode_ctx, DPE_DERIVE_CONTEXT_ALLOW_NEW_CONTEXT_TO_DERIVE,
                              &allow_new_context_to_derive);
    CHECK_AND_COUNT_OPTIONAL_ARGUMENT(decode_ctx);

    QCBORDecode_GetBoolInMapN(decode_ctx, DPE_DERIVE_CONTEXT_CREATE_CERTIFICATE,
                              &create_certificate);
    CHECK_AND_COUNT_OPTIONAL_ARGUMENT(decode_ctx);

    dpe_err = decode_dice_inputs(decode_ctx, &dice_inputs);
    if (dpe_err != DPE_NO_ERROR) {
        return dpe_err;
    }
    COUNT_ARGS(num_of_valid_arguments);

    QCBORDecode_GetByteStringInMapN(decode_ctx, DPE_DERIVE_CONTEXT_TARGET_LOCALITY,
                                    &out);
    CHECK_AND_COUNT_OPTIONAL_ARGUMENT(decode_ctx);
    if (qcbor_err == QCBOR_SUCCESS) {
        /* Valid argument was found */
        if (out.len != sizeof(target_locality)) {
            return DPE_INVALID_ARGUMENT;
        }
        memcpy(&target_locality, out.ptr, out.len);
    }

    QCBORDecode_GetBoolInMapN(decode_ctx, DPE_DERIVE_CONTEXT_RETURN_CERTIFICATE,
                              &return_certificate);
    CHECK_AND_COUNT_OPTIONAL_ARGUMENT(decode_ctx);

    QCBORDecode_GetBoolInMapN(decode_ctx, DPE_DERIVE_CONTEXT_ALLOW_NEW_CONTEXT_TO_EXPORT,
                              &allow_new_context_to_export);
    CHECK_AND_COUNT_OPTIONAL_ARGUMENT(decode_ctx);

    QCBORDecode_GetBoolInMapN(decode_ctx, DPE_DERIVE_CONTEXT_EXPORT_CDI,
                              &export_cdi);
    CHECK_AND_COUNT_OPTIONAL_ARGUMENT(decode_ctx);

    QCBORDecode_ExitMap(decode_ctx);

    /* Exit top level array */
    QCBORDecode_ExitArray(decode_ctx);

    /* Finish and check for errors before using decoded values */
    qcbor_err = QCBORDecode_Finish(decode_ctx);
    if (qcbor_err != QCBOR_SUCCESS) {
        return DPE_INVALID_COMMAND;
    }

    if (num_of_input_arguments > num_of_valid_arguments) {
        /* Extra unsupported arguments encoded in command map */
        return DPE_INVALID_ARGUMENT;
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
                                     SIZEOF_TEMP_BUF,
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
     * encode_layer_certificate(). Add it as a byte string so that its
     * decoding can be skipped and the CBOR returned to the caller.
     */
    CHECK_OVERFLOW_TO_TEMP_BUF;
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
    QCBORItem item;
    uint16_t num_of_input_arguments, num_of_valid_arguments = 0;

    /* Initialise optional parameters with their default value in case
     * they are not encoded in the input command
     */
    destroy_recursively = false;

    /* Decode Destroy context command */
    QCBORDecode_EnterMap(decode_ctx, &item);
    qcbor_err = QCBORDecode_GetError(decode_ctx);
    if ((qcbor_err != QCBOR_SUCCESS) ||
        (item.uDataType != QCBOR_TYPE_MAP)) {
            /* We expect a map of Derive Context command arguments here */
            return DPE_INVALID_COMMAND;
    }
    /* Save the number of items found in the map */
    num_of_input_arguments = item.val.uCount;

    QCBORDecode_GetByteStringInMapN(decode_ctx, DPE_DESTROY_CONTEXT_HANDLE,
                                    &out);
    qcbor_err = QCBORDecode_GetError(decode_ctx);
    if ((qcbor_err != QCBOR_SUCCESS) || (out.len != sizeof(context_handle))) {
        return DPE_INVALID_ARGUMENT;
    }
    memcpy(&context_handle, out.ptr, out.len);
    COUNT_ARGS(num_of_valid_arguments);

    QCBORDecode_GetBoolInMapN(decode_ctx, DPE_DESTROY_CONTEXT_RECURSIVELY,
                              &destroy_recursively);
    CHECK_AND_COUNT_OPTIONAL_ARGUMENT(decode_ctx);

    QCBORDecode_ExitMap(decode_ctx);

    /* Exit top level array */
    QCBORDecode_ExitArray(decode_ctx);

    /* Finish and check for errors before using decoded values */
    qcbor_err = QCBORDecode_Finish(decode_ctx);
    if (qcbor_err != QCBOR_SUCCESS) {
        return DPE_INVALID_COMMAND;
    }

    if (num_of_input_arguments > num_of_valid_arguments) {
        /* Extra unsupported arguments encoded in command map */
        return DPE_INVALID_ARGUMENT;
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
    uint8_t *certificate_buf = ALLOC_TEMP_BUF;
    size_t certificate_actual_size;
    uint8_t derived_public_key_buf[DPE_ATTEST_PUB_KEY_SIZE];
    size_t derived_public_key_actual_size;
    int new_context_handle;
    QCBORItem item;
    uint16_t num_of_input_arguments, num_of_valid_arguments = 0;

    /* Initialise optional parameters with their default value in case
     * they are not encoded in the input command
     */
    retain_context = false;
    public_key_size = 0;
    label_size = 0;

    /* Decode CertifyKey command */
    QCBORDecode_EnterMap(decode_ctx, &item);
    qcbor_err = QCBORDecode_GetError(decode_ctx);
    if ((qcbor_err != QCBOR_SUCCESS) ||
        (item.uDataType != QCBOR_TYPE_MAP)) {
            /* We expect a map of Certify Key command arguments here */
            return DPE_INVALID_COMMAND;
    }
    /* Save the number of items found in the map */
    num_of_input_arguments = item.val.uCount;

    QCBORDecode_GetByteStringInMapN(decode_ctx, DPE_CERTIFY_KEY_CONTEXT_HANDLE,
                                    &out);
    qcbor_err = QCBORDecode_GetError(decode_ctx);
    if ((qcbor_err != QCBOR_SUCCESS) || (out.len != sizeof(context_handle))) {
        return DPE_INVALID_ARGUMENT;
    }
    memcpy(&context_handle, out.ptr, out.len);
    COUNT_ARGS(num_of_valid_arguments);

    QCBORDecode_GetBoolInMapN(decode_ctx, DPE_CERTIFY_KEY_RETAIN_CONTEXT,
                              &retain_context);
    CHECK_AND_COUNT_OPTIONAL_ARGUMENT(decode_ctx);

    QCBORDecode_GetByteStringInMapN(decode_ctx, DPE_CERTIFY_KEY_PUBLIC_KEY,
                                    &out);
    CHECK_AND_COUNT_OPTIONAL_ARGUMENT(decode_ctx);
    if (qcbor_err == QCBOR_SUCCESS) {
        /* Valid argument was found */
        public_key = out.ptr;
        public_key_size = out.len;
    }

    QCBORDecode_GetByteStringInMapN(decode_ctx, DPE_CERTIFY_KEY_LABEL, &out);
    CHECK_AND_COUNT_OPTIONAL_ARGUMENT(decode_ctx);
    if (qcbor_err == QCBOR_SUCCESS) {
        /* Valid argument was found */
        label = out.ptr;
        label_size = out.len;
    }

    QCBORDecode_ExitMap(decode_ctx);

    /* Exit top level array */
    QCBORDecode_ExitArray(decode_ctx);

    /* Finish and check for errors before using decoded values */
    qcbor_err = QCBORDecode_Finish(decode_ctx);
    if (qcbor_err != QCBOR_SUCCESS) {
        return DPE_INVALID_COMMAND;
    }

    if (num_of_input_arguments > num_of_valid_arguments) {
        /* Extra unsupported arguments encoded in command map */
        return DPE_INVALID_ARGUMENT;
    }

    dpe_err = certify_key_request(context_handle, retain_context, public_key,
                                  public_key_size, label, label_size,
                                  certificate_buf,
                                  SIZEOF_TEMP_BUF,
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
    CHECK_OVERFLOW_TO_TEMP_BUF;
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
    uint8_t *certificate_chain_buf = ALLOC_TEMP_BUF;
    size_t certificate_chain_actual_size;
    int new_context_handle;
    QCBORItem item;
    uint16_t num_of_input_arguments, num_of_valid_arguments = 0;

    /* Initialise optional parameters with their default value in case
     * they are not encoded in the input command
     */
    retain_context = false;
    clear_from_context = false;

    /* Decode GetCertificateChain command */
    QCBORDecode_EnterMap(decode_ctx, &item);
    qcbor_err = QCBORDecode_GetError(decode_ctx);
    if ((qcbor_err != QCBOR_SUCCESS) ||
        (item.uDataType != QCBOR_TYPE_MAP)) {
            /* We expect a map of Get Certificate Chain command arguments here */
            return DPE_INVALID_COMMAND;
    }
    /* Save the number of items found in the map */
    num_of_input_arguments = item.val.uCount;

    QCBORDecode_GetByteStringInMapN(decode_ctx, DPE_GET_CERTIFICATE_CHAIN_CONTEXT_HANDLE,
                                    &out);
    qcbor_err = QCBORDecode_GetError(decode_ctx);
    if ((qcbor_err != QCBOR_SUCCESS) || (out.len != sizeof(context_handle))) {
        return DPE_INVALID_ARGUMENT;
    }
    memcpy(&context_handle, out.ptr, out.len);
    COUNT_ARGS(num_of_valid_arguments);

    QCBORDecode_GetBoolInMapN(decode_ctx, DPE_GET_CERTIFICATE_CHAIN_RETAIN_CONTEXT,
                              &retain_context);
    CHECK_AND_COUNT_OPTIONAL_ARGUMENT(decode_ctx);

    QCBORDecode_GetBoolInMapN(decode_ctx, DPE_GET_CERTIFICATE_CHAIN_CLEAR_FROM_CONTEXT,
                              &clear_from_context);
    CHECK_AND_COUNT_OPTIONAL_ARGUMENT(decode_ctx);

    QCBORDecode_ExitMap(decode_ctx);

    /* Exit top level array */
    QCBORDecode_ExitArray(decode_ctx);

    /* Finish and check for errors before using decoded values */
    qcbor_err = QCBORDecode_Finish(decode_ctx);
    if (qcbor_err != QCBOR_SUCCESS) {
        return DPE_INVALID_COMMAND;
    }

    if (num_of_input_arguments > num_of_valid_arguments) {
        /* Extra unsupported arguments encoded in command map */
        return DPE_INVALID_ARGUMENT;
    }

    dpe_err = get_certificate_chain_request(context_handle,
                                            retain_context,
                                            clear_from_context,
                                            certificate_chain_buf,
                                            SIZEOF_TEMP_BUF,
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
    CHECK_OVERFLOW_TO_TEMP_BUF;
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
