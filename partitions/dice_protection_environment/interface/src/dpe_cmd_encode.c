/*
 * Copyright (c) 2023-2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dice_protection_environment.h"

#include "dpe_client.h"
#include "qcbor/qcbor_encode.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"

#define DPE_CERT_CHAIN_BUF_SIZE 4096

struct derive_context_input_t {
    int context_handle;
    bool retain_parent_context;
    bool allow_new_context_to_derive;
    bool create_certificate;
    const DiceInputValues *dice_inputs;
    int32_t target_locality;
    bool return_certificate;
    bool allow_new_context_to_export;
    bool export_cdi;
};

struct derive_context_output_t {
    int new_context_handle;
    int new_parent_context_handle;
    const uint8_t *new_certificate;
    size_t new_certificate_size;
    const uint8_t *exported_cdi;
    size_t exported_cdi_size;
};

struct destroy_context_input_t {
    int context_handle;
    bool destroy_recursively;
};

struct certify_key_input_t {
    int context_handle;
    bool retain_context;
    const uint8_t *public_key;
    size_t public_key_size;
    const uint8_t *label;
    size_t label_size;
};

struct certify_key_output_t {
    const uint8_t *certificate_chain;
    size_t certificate_chain_size;
    const uint8_t *derived_public_key;
    size_t derived_public_key_size;
    int new_context_handle;
};

struct get_certificate_chain_input_t {
    int context_handle;
    bool retain_context;
    bool clear_from_context;
};
struct get_certificate_chain_output_t {
    const uint8_t *certificate_chain;
    size_t certificate_chain_size;
    int new_context_handle;
};

static void encode_dice_inputs(QCBOREncodeContext *encode_ctx,
                               const DiceInputValues *input)
{
    /* Wrap the DICE inputs into a byte string */
    QCBOREncode_BstrWrapInMapN(encode_ctx, DPE_DERIVE_CONTEXT_INPUT_DATA);

    /* Inside the byte string the DICE inputs are encoded as a map */
    QCBOREncode_OpenMap(encode_ctx);

    QCBOREncode_AddBytesToMapN(encode_ctx, DICE_CODE_HASH,
                               (UsefulBufC){ input->code_hash,
                                             sizeof(input->code_hash) });

    QCBOREncode_AddBytesToMapN(encode_ctx, DICE_CODE_DESCRIPTOR,
                              (UsefulBufC){ input->code_descriptor,
                                            input->code_descriptor_size });

    QCBOREncode_AddInt64ToMapN(encode_ctx, DICE_CONFIG_TYPE,
                               input->config_type);

    if (input->config_type == kDiceConfigTypeInline) {
        QCBOREncode_AddBytesToMapN(encode_ctx, DICE_CONFIG_VALUE,
                                   (UsefulBufC){ input->config_value,
                                                 sizeof(input->config_value) });
    } else {
        QCBOREncode_AddBytesToMapN(encode_ctx, DICE_CONFIG_DESCRIPTOR,
                                   (UsefulBufC){ input->config_descriptor,
                                                 input->config_descriptor_size });
    }

    QCBOREncode_AddBytesToMapN(encode_ctx, DICE_AUTHORITY_HASH,
                               (UsefulBufC){ input->authority_hash,
                                             sizeof(input->authority_hash) });

    QCBOREncode_AddBytesToMapN(encode_ctx, DICE_AUTHORITY_DESCRIPTOR,
                               (UsefulBufC){ input->authority_descriptor,
                                             input->authority_descriptor_size });

    QCBOREncode_AddInt64ToMapN(encode_ctx, DICE_MODE, input->mode);

    QCBOREncode_AddBytesToMapN(encode_ctx, DICE_HIDDEN,
                               (UsefulBufC){ input->hidden,
                                             sizeof(input->hidden) });

    QCBOREncode_CloseMap(encode_ctx);
    QCBOREncode_CloseBstrWrap2(encode_ctx, true, NULL);
}

static QCBORError encode_derive_context(const struct derive_context_input_t *args,
                                        UsefulBuf buf,
                                        UsefulBufC *encoded_buf)
{
    QCBOREncodeContext encode_ctx;

    QCBOREncode_Init(&encode_ctx, buf);

    QCBOREncode_OpenArray(&encode_ctx);
    QCBOREncode_AddUInt64(&encode_ctx, DPE_DERIVE_CONTEXT);

    /* Encode DeriveContext command */
    QCBOREncode_OpenMap(&encode_ctx);
    QCBOREncode_AddBytesToMapN(&encode_ctx, DPE_DERIVE_CONTEXT_CONTEXT_HANDLE,
                               (UsefulBufC){ &args->context_handle,
                                             sizeof(args->context_handle) });
    QCBOREncode_AddBoolToMapN(&encode_ctx, DPE_DERIVE_CONTEXT_RETAIN_PARENT_CONTEXT,
                              args->retain_parent_context);
    QCBOREncode_AddBoolToMapN(&encode_ctx, DPE_DERIVE_CONTEXT_ALLOW_NEW_CONTEXT_TO_DERIVE,
                              args->allow_new_context_to_derive);
    QCBOREncode_AddBoolToMapN(&encode_ctx, DPE_DERIVE_CONTEXT_CREATE_CERTIFICATE,
                              args->create_certificate);
    encode_dice_inputs(&encode_ctx, args->dice_inputs);
    QCBOREncode_AddBytesToMapN(&encode_ctx, DPE_DERIVE_CONTEXT_TARGET_LOCALITY,
                               (UsefulBufC){ &args->target_locality,
                                             sizeof(args->target_locality) });
    QCBOREncode_AddBoolToMapN(&encode_ctx, DPE_DERIVE_CONTEXT_RETURN_CERTIFICATE,
                              args->return_certificate);
    QCBOREncode_AddBoolToMapN(&encode_ctx, DPE_DERIVE_CONTEXT_ALLOW_NEW_CONTEXT_TO_EXPORT,
                              args->allow_new_context_to_export);
    QCBOREncode_AddBoolToMapN(&encode_ctx, DPE_DERIVE_CONTEXT_EXPORT_CDI,
                              args->export_cdi);
    QCBOREncode_CloseMap(&encode_ctx);

    QCBOREncode_CloseArray(&encode_ctx);

    return QCBOREncode_Finish(&encode_ctx, encoded_buf);
}

static QCBORError encode_destroy_context(const struct destroy_context_input_t *args,
                                         UsefulBuf buf,
                                         UsefulBufC *encoded_buf)
{
    QCBOREncodeContext encode_ctx;

    QCBOREncode_Init(&encode_ctx, buf);

    QCBOREncode_OpenArray(&encode_ctx);
    QCBOREncode_AddUInt64(&encode_ctx, DPE_DESTROY_CONTEXT);

    /* Encode DestroyContext command */
    QCBOREncode_OpenMap(&encode_ctx);
    QCBOREncode_AddBytesToMapN(&encode_ctx, DPE_DESTROY_CONTEXT_HANDLE,
                               (UsefulBufC){ &args->context_handle,
                                             sizeof(args->context_handle) });
    QCBOREncode_AddBoolToMapN(&encode_ctx, DPE_DESTROY_CONTEXT_RECURSIVELY,
                              args->destroy_recursively);
    QCBOREncode_CloseMap(&encode_ctx);

    QCBOREncode_CloseArray(&encode_ctx);

    return QCBOREncode_Finish(&encode_ctx, encoded_buf);
}

static QCBORError decode_derive_context_response(UsefulBufC encoded_buf,
                                                 struct derive_context_output_t *args,
                                                 dpe_error_t *dpe_err)
{
    QCBORDecodeContext decode_ctx;
    UsefulBufC out;
    int64_t response_dpe_err;

    QCBORDecode_Init(&decode_ctx, encoded_buf, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterArray(&decode_ctx, NULL);

    /* Get the error code from the response */
    QCBORDecode_GetInt64(&decode_ctx, &response_dpe_err);
    *dpe_err = (dpe_error_t)response_dpe_err;

    /* Decode DeriveContext response if successful */
    if (*dpe_err == DPE_NO_ERROR) {
        QCBORDecode_EnterMap(&decode_ctx, NULL);

        QCBORDecode_GetByteStringInMapN(&decode_ctx,
                                        DPE_DERIVE_CONTEXT_NEW_CONTEXT_HANDLE,
                                        &out);
        if (out.len != sizeof(args->new_context_handle)) {
            return QCBORDecode_Finish(&decode_ctx);
        }
        memcpy(&args->new_context_handle, out.ptr, out.len);

        QCBORDecode_GetByteStringInMapN(&decode_ctx,
                                        DPE_DERIVE_CONTEXT_PARENT_CONTEXT_HANDLE,
                                        &out);
        if (out.len != sizeof(args->new_parent_context_handle)) {
            return QCBORDecode_Finish(&decode_ctx);
        }
        memcpy(&args->new_parent_context_handle, out.ptr, out.len);

        QCBORDecode_GetByteStringInMapN(&decode_ctx,
                                        DPE_DERIVE_CONTEXT_NEW_CERTIFICATE,
                                        &out);
        args->new_certificate = out.ptr;
        args->new_certificate_size = out.len;

        QCBORDecode_GetByteStringInMapN(&decode_ctx,
                                        DPE_DERIVE_CONTEXT_EXPORTED_CDI,
                                        &out);
        args->exported_cdi = out.ptr;
        args->exported_cdi_size = out.len;

        QCBORDecode_ExitMap(&decode_ctx);
    }

    QCBORDecode_ExitArray(&decode_ctx);

    return QCBORDecode_Finish(&decode_ctx);
}

static QCBORError decode_destroy_context_response(UsefulBufC encoded_buf,
                                                  dpe_error_t *dpe_err)
{
    QCBORDecodeContext decode_ctx;
    int64_t response_dpe_err;

    QCBORDecode_Init(&decode_ctx, encoded_buf, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterArray(&decode_ctx, NULL);

    /* Get the error code from the response */
    QCBORDecode_GetInt64(&decode_ctx, &response_dpe_err);
    *dpe_err = (dpe_error_t)response_dpe_err;

    QCBORDecode_ExitArray(&decode_ctx);

    return QCBORDecode_Finish(&decode_ctx);
}

static QCBORError encode_certify_key(const struct certify_key_input_t *args,
                                     UsefulBuf buf,
                                     UsefulBufC *encoded_buf)
{
    QCBOREncodeContext encode_ctx;

    QCBOREncode_Init(&encode_ctx, buf);

    QCBOREncode_OpenArray(&encode_ctx);
    QCBOREncode_AddUInt64(&encode_ctx, DPE_CERTIFY_KEY);

    /* Encode CertifyKey command */
    QCBOREncode_OpenMap(&encode_ctx);
    QCBOREncode_AddBytesToMapN(&encode_ctx, DPE_CERTIFY_KEY_CONTEXT_HANDLE,
                               (UsefulBufC){ &args->context_handle,
                                             sizeof(args->context_handle) });
    QCBOREncode_AddBoolToMapN(&encode_ctx, DPE_CERTIFY_KEY_RETAIN_CONTEXT,
                              args->retain_context);
    QCBOREncode_AddBytesToMapN(&encode_ctx, DPE_CERTIFY_KEY_PUBLIC_KEY,
                               (UsefulBufC){ args->public_key,
                                             args->public_key_size });
    QCBOREncode_AddBytesToMapN(&encode_ctx, DPE_CERTIFY_KEY_LABEL,
                               (UsefulBufC){ args->label, args->label_size} );
    QCBOREncode_CloseMap(&encode_ctx);

    QCBOREncode_CloseArray(&encode_ctx);

    return QCBOREncode_Finish(&encode_ctx, encoded_buf);
}

static QCBORError decode_certify_key_response(UsefulBufC encoded_buf,
                                              struct certify_key_output_t *args,
                                              dpe_error_t *dpe_err)
{
    QCBORDecodeContext decode_ctx;
    UsefulBufC out;
    int64_t response_dpe_err;

    QCBORDecode_Init(&decode_ctx, encoded_buf, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterArray(&decode_ctx, NULL);

    /* Get the error code from the response */
    QCBORDecode_GetInt64(&decode_ctx, &response_dpe_err);
    *dpe_err = (dpe_error_t)response_dpe_err;

    /* Decode CertifyKey response if successful */
    if (*dpe_err == DPE_NO_ERROR) {
        QCBORDecode_EnterMap(&decode_ctx, NULL);

        QCBORDecode_GetByteStringInMapN(&decode_ctx,
                                        DPE_CERTIFY_KEY_CERTIFICATE,
                                        &out);
        args->certificate_chain = out.ptr;
        args->certificate_chain_size = out.len;

        QCBORDecode_GetByteStringInMapN(&decode_ctx,
                                        DPE_CERTIFY_KEY_DERIVED_PUBLIC_KEY,
                                        &out);
        args->derived_public_key = out.ptr;
        args->derived_public_key_size = out.len;

        QCBORDecode_GetByteStringInMapN(&decode_ctx,
                                        DPE_CERTIFY_KEY_NEW_CONTEXT_HANDLE,
                                        &out);
        if (out.len != sizeof(args->new_context_handle)) {
            return QCBORDecode_Finish(&decode_ctx);
        }
        memcpy(&args->new_context_handle, out.ptr, out.len);

        QCBORDecode_ExitMap(&decode_ctx);
    }

    QCBORDecode_ExitArray(&decode_ctx);

    return QCBORDecode_Finish(&decode_ctx);
}

static QCBORError encode_get_certificate_chain(const struct get_certificate_chain_input_t *args,
                                               UsefulBuf buf,
                                               UsefulBufC *encoded_buf)
{
    QCBOREncodeContext encode_ctx;

    QCBOREncode_Init(&encode_ctx, buf);

    QCBOREncode_OpenArray(&encode_ctx);
    QCBOREncode_AddUInt64(&encode_ctx, DPE_GET_CERTIFICATE_CHAIN);

    /* Encode GetCertificateChain command */
    QCBOREncode_OpenMap(&encode_ctx);
    QCBOREncode_AddBytesToMapN(&encode_ctx, DPE_GET_CERTIFICATE_CHAIN_CONTEXT_HANDLE,
                               (UsefulBufC){ &args->context_handle,
                                             sizeof(args->context_handle) });
    QCBOREncode_AddBoolToMapN(&encode_ctx, DPE_GET_CERTIFICATE_CHAIN_RETAIN_CONTEXT,
                              args->retain_context);
    QCBOREncode_AddBoolToMapN(&encode_ctx, DPE_GET_CERTIFICATE_CHAIN_CLEAR_FROM_CONTEXT,
                              args->clear_from_context);
    QCBOREncode_CloseMap(&encode_ctx);

    QCBOREncode_CloseArray(&encode_ctx);

    return QCBOREncode_Finish(&encode_ctx, encoded_buf);
}

static QCBORError decode_get_certificate_chain_response(UsefulBufC encoded_buf,
                                                        struct get_certificate_chain_output_t *args,
                                                        dpe_error_t *dpe_err)
{
    QCBORDecodeContext decode_ctx;
    UsefulBufC out;
    int64_t response_dpe_err;

    QCBORDecode_Init(&decode_ctx, encoded_buf, QCBOR_DECODE_MODE_NORMAL);

    QCBORDecode_EnterArray(&decode_ctx, NULL);

    /* Get the error code from the response */
    QCBORDecode_GetInt64(&decode_ctx, &response_dpe_err);
    *dpe_err = (dpe_error_t)response_dpe_err;

    /* Decode CertifyKey response if successful */
    if (*dpe_err == DPE_NO_ERROR) {
        QCBORDecode_EnterMap(&decode_ctx, NULL);

        QCBORDecode_GetByteStringInMapN(&decode_ctx,
                                        DPE_GET_CERTIFICATE_CHAIN_CERTIFICATE_CHAIN,
                                        &out);
        args->certificate_chain = out.ptr;
        args->certificate_chain_size = out.len;

        QCBORDecode_GetByteStringInMapN(&decode_ctx,
                                        DPE_GET_CERTIFICATE_CHAIN_NEW_CONTEXT_HANDLE,
                                        &out);
        if (out.len != sizeof(args->new_context_handle)) {
            return QCBORDecode_Finish(&decode_ctx);
        }
        memcpy(&args->new_context_handle, out.ptr, out.len);

        QCBORDecode_ExitMap(&decode_ctx);
    }

    QCBORDecode_ExitArray(&decode_ctx);

    return QCBORDecode_Finish(&decode_ctx);
}

dpe_error_t
dpe_derive_context(int                    context_handle,
                   bool                   retain_parent_context,
                   bool                   allow_new_context_to_derive,
                   bool                   create_certificate,
                   const DiceInputValues *dice_inputs,
                   int32_t                target_locality,
                   bool                   return_certificate,
                   bool                   allow_new_context_to_export,
                   bool                   export_cdi,
                   int                   *new_context_handle,
                   int                   *new_parent_context_handle,
                   uint8_t               *new_certificate_buf,
                   size_t                 new_certificate_buf_size,
                   size_t                *new_certificate_actual_size,
                   uint8_t               *exported_cdi_buf,
                   size_t                 exported_cdi_buf_size,
                   size_t                *exported_cdi_actual_size)
{
    int32_t service_err;
    dpe_error_t dpe_err;
    QCBORError qcbor_err;
    UsefulBufC encoded_buf;
    UsefulBuf_MAKE_STACK_UB(cmd_buf, 612);

    const struct derive_context_input_t in_args = {
        context_handle,
        retain_parent_context,
        allow_new_context_to_derive,
        create_certificate,
        dice_inputs,
        target_locality,
        return_certificate,
        allow_new_context_to_export,
        export_cdi,
    };
    struct derive_context_output_t out_args;

    /* Validate the output params. Input params are validated by DPE service */
    if ((new_context_handle == NULL) ||
        (retain_parent_context && new_parent_context_handle == NULL) ||
        (return_certificate &&
        (new_certificate_buf == NULL || new_certificate_actual_size == NULL)) ||
        (export_cdi &&
        (exported_cdi_buf == NULL || exported_cdi_actual_size == NULL))) {
        return DPE_INVALID_ARGUMENT;
    }

    qcbor_err = encode_derive_context(&in_args, cmd_buf, &encoded_buf);
    if (qcbor_err != QCBOR_SUCCESS) {
        return DPE_INTERNAL_ERROR;
    }

    service_err = dpe_client_call(encoded_buf.ptr, encoded_buf.len,
                                  cmd_buf.ptr, &cmd_buf.len);
    if (service_err != 0) {
        return DPE_INTERNAL_ERROR;
    }

    qcbor_err = decode_derive_context_response(UsefulBuf_Const(cmd_buf),
                                               &out_args, &dpe_err);
    if (qcbor_err != QCBOR_SUCCESS) {
        return DPE_INTERNAL_ERROR;
    } else if (dpe_err != DPE_NO_ERROR) {
        return dpe_err;
    }

    /* Copy returned values into caller's memory */
    *new_context_handle = out_args.new_context_handle;
    if (retain_parent_context) {
        *new_parent_context_handle = out_args.new_parent_context_handle;
    }

    if (return_certificate) {
        if (out_args.new_certificate_size > new_certificate_buf_size) {
            return DPE_INVALID_ARGUMENT;
        }
        memcpy(new_certificate_buf, out_args.new_certificate,
               out_args.new_certificate_size);
        *new_certificate_actual_size = out_args.new_certificate_size;
    }

    if (export_cdi) {
        if (out_args.exported_cdi_size > exported_cdi_buf_size) {
            return DPE_INVALID_ARGUMENT;
        }
        memcpy(exported_cdi_buf, out_args.exported_cdi,
               out_args.exported_cdi_size);
        *exported_cdi_actual_size = out_args.exported_cdi_size;
    }

    return DPE_NO_ERROR;
}

dpe_error_t dpe_destroy_context(int context_handle, bool destroy_recursively)
{
    int32_t service_err;
    dpe_error_t dpe_err;
    QCBORError qcbor_err;
    UsefulBufC encoded_buf;
    UsefulBuf_MAKE_STACK_UB(cmd_buf, 12);

    const struct destroy_context_input_t in_args = {
        context_handle,
        destroy_recursively
    };

    qcbor_err = encode_destroy_context(&in_args, cmd_buf, &encoded_buf);
    if (qcbor_err != QCBOR_SUCCESS) {
        return DPE_INTERNAL_ERROR;
    }

    service_err = dpe_client_call(encoded_buf.ptr, encoded_buf.len,
                                  cmd_buf.ptr, &cmd_buf.len);
    if (service_err != 0) {
        return DPE_INTERNAL_ERROR;
    }

    qcbor_err = decode_destroy_context_response(UsefulBuf_Const(cmd_buf),
                                                &dpe_err);
    if (qcbor_err != QCBOR_SUCCESS) {
        return DPE_INTERNAL_ERROR;
    } else if (dpe_err != DPE_NO_ERROR) {
        return dpe_err;
    }

    return DPE_NO_ERROR;
}

dpe_error_t dpe_certify_key(int context_handle,
                            bool retain_context,
                            const uint8_t *public_key,
                            size_t public_key_size,
                            const uint8_t *label,
                            size_t label_size,
                            uint8_t *certificate_chain_buf,
                            size_t certificate_chain_buf_size,
                            size_t *certificate_chain_actual_size,
                            uint8_t *derived_public_key_buf,
                            size_t derived_public_key_buf_size,
                            size_t *derived_public_key_actual_size,
                            int *new_context_handle)
{
    int32_t service_err;
    dpe_error_t dpe_err;
    QCBORError qcbor_err;
    UsefulBufC encoded_buf;
    UsefulBuf_MAKE_STACK_UB(cmd_buf, 2500);

    const struct certify_key_input_t in_args = {
        context_handle,
        retain_context,
        public_key,
        public_key_size,
        label,
        label_size,
    };
    struct certify_key_output_t out_args;

    /* Validate the output params. Input params are validated by DPE service */
    if ((retain_context && new_context_handle == NULL) ||
        (certificate_chain_buf == NULL || certificate_chain_actual_size == NULL) ||
        (public_key == NULL &&
        (derived_public_key_buf == NULL || derived_public_key_actual_size == NULL))) {
        return DPE_INVALID_ARGUMENT;
    }

    qcbor_err = encode_certify_key(&in_args, cmd_buf, &encoded_buf);
    if (qcbor_err != QCBOR_SUCCESS) {
        return DPE_INTERNAL_ERROR;
    }

    service_err = dpe_client_call(encoded_buf.ptr, encoded_buf.len,
                                  cmd_buf.ptr, &cmd_buf.len);
    if (service_err != 0) {
        return DPE_INTERNAL_ERROR;
    }

    qcbor_err = decode_certify_key_response(UsefulBuf_Const(cmd_buf),
                                            &out_args, &dpe_err);
    if (qcbor_err != QCBOR_SUCCESS) {
        return DPE_INTERNAL_ERROR;
    } else if (dpe_err != DPE_NO_ERROR) {
        return dpe_err;
    }

    /* Copy returned values into caller's memory */
    if (out_args.certificate_chain_size > certificate_chain_buf_size) {
        return DPE_INVALID_ARGUMENT;
    }
    memcpy(certificate_chain_buf, out_args.certificate_chain,
           out_args.certificate_chain_size);
    *certificate_chain_actual_size = out_args.certificate_chain_size;

    if (public_key == NULL) {
        if (out_args.derived_public_key_size > derived_public_key_buf_size) {
            return DPE_INVALID_ARGUMENT;
        }
        memcpy(derived_public_key_buf, out_args.derived_public_key,
               out_args.derived_public_key_size);
        *derived_public_key_actual_size = out_args.derived_public_key_size;
    }

    if (retain_context) {
        *new_context_handle = out_args.new_context_handle;
    }

    return DPE_NO_ERROR;
}

dpe_error_t
dpe_get_certificate_chain(int            context_handle,
                          bool           retain_context,
                          bool           clear_from_context,
                          uint8_t       *certificate_chain_buf,
                          size_t         certificate_chain_buf_size,
                          size_t        *certificate_chain_actual_size,
                          int           *new_context_handle)
{
    int32_t service_err;
    dpe_error_t dpe_err;
    QCBORError qcbor_err;
    UsefulBufC encoded_buf;
    UsefulBuf_MAKE_STACK_UB(cmd_buf, DPE_CERT_CHAIN_BUF_SIZE);

    const struct get_certificate_chain_input_t in_args = {
        context_handle,
        retain_context,
        clear_from_context
    };
    struct get_certificate_chain_output_t out_args;

    /* Validate the output params. Input params are validated by DPE service */
    if ((retain_context && new_context_handle == NULL) ||
        (certificate_chain_buf == NULL || certificate_chain_actual_size == NULL)) {
        return DPE_INVALID_ARGUMENT;
    }

    qcbor_err = encode_get_certificate_chain(&in_args, cmd_buf, &encoded_buf);
    if (qcbor_err != QCBOR_SUCCESS) {
        return DPE_INTERNAL_ERROR;
    }

    service_err = dpe_client_call(encoded_buf.ptr, encoded_buf.len,
                                  cmd_buf.ptr, &cmd_buf.len);
    if (service_err != 0) {
        return DPE_INTERNAL_ERROR;
    }

    qcbor_err = decode_get_certificate_chain_response(UsefulBuf_Const(cmd_buf),
                                                                      &out_args,
                                                                      &dpe_err);
    if (qcbor_err != QCBOR_SUCCESS) {
        return DPE_INTERNAL_ERROR;
    } else if (dpe_err != DPE_NO_ERROR) {
        return dpe_err;
    }

    /* Copy returned values into caller's memory */
    if (out_args.certificate_chain_size > certificate_chain_buf_size) {
        return DPE_INVALID_ARGUMENT;
    }
    memcpy(certificate_chain_buf, out_args.certificate_chain,
           out_args.certificate_chain_size);
    *certificate_chain_actual_size = out_args.certificate_chain_size;

    if (retain_context) {
        *new_context_handle = out_args.new_context_handle;
    }

    return DPE_NO_ERROR;
}
