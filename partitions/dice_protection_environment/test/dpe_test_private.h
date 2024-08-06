/*
 * Copyright (c) 2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __DPE_TEST_PRIVATE_H__
#define __DPE_TEST_PRIVATE_H__

#include "psa/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Below defined values MUST be identical to service internal definitions (dpe_context_mngr.h) */
#define INVALID_HANDLE 0xFFFFFFFF
#define ROT_CTX_HANDLE 0

#ifndef DPE_ATTEST_PUB_KEY_SIZE
#define DPE_ATTEST_PUB_KEY_SIZE PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(521)
#endif

/* Below encoded CDI size accomodate both Attest and Seal CDI */
#define DICE_MAX_ENCODED_CDI_SIZE ((2 * DICE_CDI_SIZE) + 16)

/* Most significant 16 bits represent nonce & remaining 16 bits represent component index */
#ifndef GET_IDX
#define GET_IDX(handle) (handle & 0xffff)
#define GET_NONCE(handle) ((handle >> 16) & 0xffff)
#define SET_IDX(handle, idx) ((handle & 0xffff0000) | idx)
#define SET_NONCE(handle, nonce) ((handle & 0x00ffff) | (nonce << 16))
#endif

#define DESTROY_SINGLE_CONTEXT(ctx_handle)                  \
    dpe_err = dpe_destroy_context(ctx_handle, false);       \
    if (dpe_err != DPE_NO_ERROR) {                          \
        TEST_FAIL("DPE DestroyContext call failed");        \
        return;                                             \
    }

#define CALL_DERIVE_CONTEXT_WITH_TEST_PARAM(dc_input, dc_output, test_params)   \
    dpe_derive_context_with_test_param(                                         \
        dc_input.context_handle, /* input_ctx_handle */                         \
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

#define CALL_CERTIFY_KEY_WITH_TEST_PARAM(ck_input, ck_output, test_params)  \
    dpe_certify_key_with_test_param(                                        \
        ck_input.context_handle, /* input_ctx_handle */                     \
        ck_input.retain_context,                                            \
        ck_input.public_key,                                                \
        ck_input.public_key_size,                                           \
        ck_input.label,                                                     \
        ck_input.label_size,                                                \
        ck_output.certificate_chain_buf,                                    \
        ck_output.certificate_chain_buf_size,                               \
        &ck_output.certificate_chain_actual_size,                           \
        ck_output.derived_public_key_buf,                                   \
        ck_output.derived_public_key_buf_size,                              \
        &ck_output.derived_public_key_actual_size,                          \
        &ck_output.new_context_handle,                                      \
        &test_params);                    /* test_params */

#define ADD_CERT_CHAIN_BUF(ck_output, size)                     \
    uint8_t certificate_chain_buf[size];                        \
    ck_output.certificate_chain_buf = certificate_chain_buf;    \
    ck_output.certificate_chain_buf_size = size

#define ADD_DERIVED_PUB_KEY_BUF(ck_output, size)                \
    uint8_t derived_public_key_buf[size];                       \
    ck_output.derived_public_key_buf = derived_public_key_buf;  \
    ck_output.derived_public_key_buf_size = size

#define CALL_CERTIFY_KEY(ck_input, ck_output)                       \
    dpe_certify_key(ck_input.context_handle,                        \
        ck_input.retain_context,                                    \
        ck_input.public_key,                                        \
        ck_input.public_key_size,                                   \
        ck_input.label,                                             \
        ck_input.label_size,                                        \
        ck_output.certificate_chain_buf,                            \
        ck_output.certificate_chain_buf_size,                       \
        &ck_output.certificate_chain_actual_size,                   \
        ck_output.derived_public_key_buf,                           \
        ck_output.derived_public_key_buf_size,                      \
        &ck_output.derived_public_key_actual_size,                  \
        &ck_output.new_context_handle)

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

struct certify_key_cmd_input_t {
    int             context_handle;
    bool            retain_context;
    const uint8_t   *public_key;
    size_t          public_key_size;
    const uint8_t   *label;
    size_t          label_size;
};

struct certify_key_cmd_output_t {
    uint8_t         *certificate_chain_buf;
    size_t          certificate_chain_buf_size;
    size_t          certificate_chain_actual_size;
    uint8_t         *derived_public_key_buf;
    size_t          derived_public_key_buf_size;
    size_t          derived_public_key_actual_size;
    int             new_context_handle;
};

#ifdef __cplusplus
}
#endif

#endif /* __DPE_TEST_PRIVATE_H__ */
