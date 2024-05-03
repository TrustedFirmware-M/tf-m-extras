/*
 * Copyright (c) 2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __DPE_TEST_PRIVATE_H__
#define __DPE_TEST_PRIVATE_H__

#ifdef __cplusplus
extern "C" {
#endif

#define DESTROY_SINGLE_CONTEXT(ctx_handle)                  \
    dpe_err = dpe_destroy_context(ctx_handle, false);       \
    if (dpe_err != DPE_NO_ERROR) {                          \
        TEST_FAIL("DPE DestroyContext call failed");        \
        return;                                             \
    }

#define CALL_DERIVE_CONTEXT_WITH_TEST_PARAM(dc_input, dc_output, test_params)   \
    dpe_derive_context_with_test_param(                                         \
        retained_rot_ctx_handle, /* input_ctx_handle */                         \
        dc_input.cert_id,                                                       \
        dc_input.retain_parent_context,                                         \
        dc_input.allow_new_context_to_derive,                                   \
        dc_input.create_certificate,                                            \
        &dc_input.dice_inputs,                                                  \
        dc_input.target_locality,                                               \
        dc_input.return_certificate,                                            \
        dc_input.allow_new_context_to_export,                                   \
        dc_input.export_cdi,                                                    \
        &dc_output.out_ctx_handle,                                              \
        &dc_output.out_parent_handle,                                           \
        dc_output.certificate_buf,                                              \
        dc_output.certificate_buf_size,                                         \
        &dc_output.certificate_actual_size,                                     \
        dc_output.exported_cdi_buf,                                             \
        dc_output.exported_cdi_buf_size,                                        \
        &dc_output.exported_cdi_actual_size,                                    \
        &test_params);              /* test_parameters */

#define ADD_CERT_BUF(dc_output, size)               \
    uint8_t certificate_buf[size];                  \
    dc_output.certificate_buf = certificate_buf;    \
    dc_output.certificate_buf_size = size

#define ADD_EXPORT_CDI_BUF(dc_output, size)         \
    uint8_t exported_cdi_buf[size];                 \
    dc_output.exported_cdi_buf = exported_cdi_buf;  \
    dc_output.exported_cdi_buf_size = size

#define CALL_DERIVE_CONTEXT(dc_input, dc_output)    \
    dpe_derive_context(dc_input.context_handle,     \
        dc_input.cert_id,                           \
        dc_input.retain_parent_context,             \
        dc_input.allow_new_context_to_derive,       \
        dc_input.create_certificate,                \
        &dc_input.dice_inputs,                      \
        dc_input.target_locality,                   \
        dc_input.return_certificate,                \
        dc_input.allow_new_context_to_export,       \
        dc_input.export_cdi,                        \
        &dc_output.out_ctx_handle,                  \
        &dc_output.out_parent_handle,               \
        dc_output.certificate_buf,                  \
        dc_output.certificate_buf_size,             \
        &dc_output.certificate_actual_size,         \
        dc_output.exported_cdi_buf,                 \
        dc_output.exported_cdi_buf_size,            \
        &dc_output.exported_cdi_actual_size)

struct derive_context_cmd_input_t {
    int             context_handle;
    uint32_t        cert_id;
    bool            retain_parent_context;
    bool            allow_new_context_to_derive;
    bool            create_certificate;
    DiceInputValues dice_inputs;
    int32_t         target_locality;
    bool            return_certificate;
    bool            allow_new_context_to_export;
    bool            export_cdi;
};

struct derive_context_cmd_output_t {
    int             out_ctx_handle;
    int             out_parent_handle;
    uint8_t         *certificate_buf;
    size_t          certificate_buf_size;
    size_t          certificate_actual_size;
    uint8_t         *exported_cdi_buf;
    size_t          exported_cdi_buf_size;
    size_t          exported_cdi_actual_size;
};

#ifdef __cplusplus
}
#endif

#endif /* __DPE_TEST_PRIVATE_H__ */
