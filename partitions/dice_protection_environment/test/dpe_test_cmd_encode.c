/*
 * Copyright (c) 2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dice_protection_environment.h"
#include "dpe_test_data.h"

#include "dpe_client.h"
#include "dpe_cmd_encode.h"
#include "qcbor/qcbor_encode.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"

#define DPE_UNSUPPORTED_PARAMS_LABEL 900

static void encode_dice_inputs(QCBOREncodeContext *encode_ctx,
                               const DiceInputValues *input,
                               struct dpe_derive_context_test_params_t *test_params)
{
    /* Wrap the DICE inputs into a byte string */
    QCBOREncode_BstrWrapInMapN(encode_ctx, DPE_DERIVE_CONTEXT_INPUT_DATA);

    /* Inside the byte string the DICE inputs are encoded as a map */
    QCBOREncode_OpenMap(encode_ctx);

    if (!test_params->is_code_hash_missing) {
     QCBOREncode_AddBytesToMapN(encode_ctx, DICE_CODE_HASH,
                                (UsefulBufC){ input->code_hash,
                                              sizeof(input->code_hash) });
    }

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
        if (!test_params->is_config_descriptor_missing) {
            QCBOREncode_AddBytesToMapN(encode_ctx, DICE_CONFIG_DESCRIPTOR,
                                       (UsefulBufC){ input->config_descriptor,
                                                     input->config_descriptor_size });
        }
    }

    if (!test_params->is_authority_hash_missing) {
        QCBOREncode_AddBytesToMapN(encode_ctx, DICE_AUTHORITY_HASH,
                                   (UsefulBufC){ input->authority_hash,
                                                 sizeof(input->authority_hash) });
    }

    QCBOREncode_AddBytesToMapN(encode_ctx, DICE_AUTHORITY_DESCRIPTOR,
                               (UsefulBufC){ input->authority_descriptor,
                                             input->authority_descriptor_size });

    if (!test_params->is_mode_missing) {
        QCBOREncode_AddInt64ToMapN(encode_ctx, DICE_MODE, input->mode);
    }

    QCBOREncode_AddBytesToMapN(encode_ctx, DICE_HIDDEN,
                               (UsefulBufC){ input->hidden,
                                             sizeof(input->hidden) });

    QCBOREncode_CloseMap(encode_ctx);
    QCBOREncode_CloseBstrWrap2(encode_ctx, true, NULL);
}

static QCBORError encode_derive_context(const struct derive_context_input_t *args,
                                        UsefulBuf buf,
                                        UsefulBufC *encoded_buf,
                                        struct dpe_derive_context_test_params_t *test_params)
{
    QCBOREncodeContext encode_ctx;
    bool unsupported_param_val = true;

    QCBOREncode_Init(&encode_ctx, buf);

    QCBOREncode_OpenArray(&encode_ctx);
    QCBOREncode_AddUInt64(&encode_ctx, DPE_DERIVE_CONTEXT);

    /* Encode DeriveContext command */
    QCBOREncode_OpenMap(&encode_ctx);
    QCBOREncode_AddBytesToMapN(&encode_ctx, DPE_DERIVE_CONTEXT_CONTEXT_HANDLE,
                               (UsefulBufC){ &args->context_handle,
                                             sizeof(args->context_handle) });
    if (!test_params->is_cert_id_missing) {
        QCBOREncode_AddUInt64ToMapN(&encode_ctx, DPE_DERIVE_CONTEXT_CERT_ID,
                                    args->cert_id);
    }

    if (!test_params->is_retain_parent_context_missing) {
        QCBOREncode_AddBoolToMapN(&encode_ctx, DPE_DERIVE_CONTEXT_RETAIN_PARENT_CONTEXT,
                                args->retain_parent_context);
    }
    if (!test_params->is_allow_new_context_to_derive_missing) {
        QCBOREncode_AddBoolToMapN(&encode_ctx, DPE_DERIVE_CONTEXT_ALLOW_NEW_CONTEXT_TO_DERIVE,
                                  args->allow_new_context_to_derive);
    }
    if (!test_params->is_create_certificate_missing) {
        QCBOREncode_AddBoolToMapN(&encode_ctx, DPE_DERIVE_CONTEXT_CREATE_CERTIFICATE,
                                  args->create_certificate);
    }
    if (!test_params->is_input_dice_data_missing) {
        encode_dice_inputs(&encode_ctx, args->dice_inputs, test_params);
    }
    QCBOREncode_AddBytesToMapN(&encode_ctx, DPE_DERIVE_CONTEXT_TARGET_LOCALITY,
                               (UsefulBufC){ &args->target_locality,
                                             sizeof(args->target_locality) });
    if (!test_params->is_return_certificate_missing) {
        QCBOREncode_AddBoolToMapN(&encode_ctx, DPE_DERIVE_CONTEXT_RETURN_CERTIFICATE,
                                  args->return_certificate);
    }
    if (!test_params->is_allow_new_context_to_export_missing) {
        QCBOREncode_AddBoolToMapN(&encode_ctx, DPE_DERIVE_CONTEXT_ALLOW_NEW_CONTEXT_TO_EXPORT,
                                  args->allow_new_context_to_export);
    }
    if (!test_params->is_export_cdi_missing) {
        QCBOREncode_AddBoolToMapN(&encode_ctx, DPE_DERIVE_CONTEXT_EXPORT_CDI,
                                  args->export_cdi);
    }
    if (test_params->is_unsupported_params_added) {
        /* Encode additional unsupported params */
        QCBOREncode_AddBoolToMapN(&encode_ctx, DPE_UNSUPPORTED_PARAMS_LABEL,
                                  unsupported_param_val);
    }

    QCBOREncode_CloseMap(&encode_ctx);

    if (test_params->is_encoded_cbor_corrupt) {
        /* Deliberately corrupt CBOR map metadata and construct */
        *((uint8_t *)encode_ctx.OutBuf.UB.ptr + 1) = 0xff;
    }

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

static QCBORError encode_certify_key(const struct certify_key_input_t *args,
                                     UsefulBuf buf,
                                     UsefulBufC *encoded_buf,
                                     struct dpe_certify_key_test_params_t *test_params)
{
    QCBOREncodeContext encode_ctx;
    bool unsupported_param_val = true;

    QCBOREncode_Init(&encode_ctx, buf);

    QCBOREncode_OpenArray(&encode_ctx);
    QCBOREncode_AddUInt64(&encode_ctx, DPE_CERTIFY_KEY);

    /* Encode CertifyKey command */
    QCBOREncode_OpenMap(&encode_ctx);
    QCBOREncode_AddBytesToMapN(&encode_ctx, DPE_CERTIFY_KEY_CONTEXT_HANDLE,
                               (UsefulBufC){ &args->context_handle,
                                             sizeof(args->context_handle) });
    if (!test_params->is_retain_context_missing) {
        QCBOREncode_AddBoolToMapN(&encode_ctx, DPE_CERTIFY_KEY_RETAIN_CONTEXT,
                                  args->retain_context);
    }
    if (!test_params->is_public_key_missing) {
        QCBOREncode_AddBytesToMapN(&encode_ctx, DPE_CERTIFY_KEY_PUBLIC_KEY,
                                   (UsefulBufC){ args->public_key,
                                                 args->public_key_size });
    }
    if (!test_params->is_label_missing) {
        QCBOREncode_AddBytesToMapN(&encode_ctx, DPE_CERTIFY_KEY_LABEL,
                                   (UsefulBufC){ args->label, args->label_size} );
    }
    if (test_params->is_unsupported_params_added) {
        /* Encode additional unsupported params */
        QCBOREncode_AddBoolToMapN(&encode_ctx, DPE_UNSUPPORTED_PARAMS_LABEL,
                                  unsupported_param_val);
    }

    QCBOREncode_CloseMap(&encode_ctx);

    if (test_params->is_encoded_cbor_corrupt) {
        /* Deliberately corrupt CBOR map metadata and construct */
        *((uint8_t *)encode_ctx.OutBuf.UB.ptr + 1) = 0xff;
    }

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

dpe_error_t
dpe_derive_context_with_test_param(int    context_handle,
                   uint32_t               cert_id,
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
                   size_t                *exported_cdi_actual_size,
                   struct dpe_derive_context_test_params_t *test_params)
{
    int32_t service_err;
    dpe_error_t dpe_err;
    QCBORError qcbor_err;
    UsefulBufC encoded_buf;
    UsefulBuf_MAKE_STACK_UB(cmd_buf, DICE_CERT_SIZE);

    const struct derive_context_input_t in_args = {
        context_handle,
        cert_id,
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

    qcbor_err = encode_derive_context(&in_args, cmd_buf, &encoded_buf, test_params);
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
    } else {
        *new_certificate_actual_size = 0;
    }

    if (export_cdi) {
        if (out_args.exported_cdi_size > exported_cdi_buf_size) {
            return DPE_INVALID_ARGUMENT;
        }
        memcpy(exported_cdi_buf, out_args.exported_cdi,
               out_args.exported_cdi_size);
        *exported_cdi_actual_size = out_args.exported_cdi_size;
    } else {
        *exported_cdi_actual_size = 0;
    }

    return DPE_NO_ERROR;
}

dpe_error_t dpe_certify_key_with_test_param(int context_handle,
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
                            int *new_context_handle,
                            struct dpe_certify_key_test_params_t *test_params)
{
    int32_t service_err;
    dpe_error_t dpe_err;
    QCBORError qcbor_err;
    UsefulBufC encoded_buf;
    UsefulBuf_MAKE_STACK_UB(cmd_buf, DICE_CERT_SIZE);

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

    qcbor_err = encode_certify_key(&in_args, cmd_buf, &encoded_buf, test_params);
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
    /* Output buffer sizes are checked by client side API implementation and
     * not by DPE service. Until allocated buffer sizes are passed to the service,
     * and checked if their size is sufficient, return output handle
     * from the command
     */
    *new_context_handle = out_args.new_context_handle;

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

    return DPE_NO_ERROR;
}
