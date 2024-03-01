/*
 * Copyright (c) 2023-2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __DPE_DERIVE_CONTEXT_TEST_DATA_H__
#define __DPE_DERIVE_CONTEXT_TEST_DATA_H__

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_NUM_OF_COMPONENTS 20
#define INVALID_COMPONENT_IDX 0xFFFF

#define DPE_PLATFORM_CERT_ID 0x200
/* Certificate IDs used for tests where layers are finalized and undestroyable
 * contexts are created (i.e. no valid handle is returned for the context)
 */
#define DPE_UNDESTROYABLE_CTX_CERT_ID_1 0x901
#define DPE_UNDESTROYABLE_CTX_CERT_ID_2 0x902
#define DPE_UNDESTROYABLE_CTX_CERT_ID_3 0x903
#define DPE_UNDESTROYABLE_CTX_CERT_ID_4 0x904
#define DPE_UNDESTROYABLE_CTX_CERT_ID_5 0x905

#define DERIVE_CONTEXT_TEST_DATA1_SIZE 3
#define DERIVE_CONTEXT_TEST_DATA2_SIZE 1

#define DEFAULT_DICE_INPUT {                               \
        { 0xC0, 0xDE },                                    \
        (uint8_t[]){ 0xC0, 0xDE, 0xDE, 0x5C },             \
        sizeof((uint8_t[]){ 0xC0, 0xDE, 0xDE, 0x5C }),     \
        kDiceConfigTypeDescriptor,                         \
        { 0xC0, 0x9F, 0x16 },                              \
        (uint8_t[]){ 0xC0, 0x9F, 0xDE, 0x5C },             \
        sizeof((uint8_t[]){ 0xC0, 0x9F, 0xDE, 0x5C }),     \
        { 0x47, 0x07 },                                    \
        (uint8_t[]){ 0x47, 0x07, 0xDE, 0x5C },             \
        sizeof((uint8_t[]){ 0x47, 0x07, 0xDE, 0x5C }),     \
        kDiceModeDebug,                                    \
        { 0x81, 0xDE },                                    \
    }

struct dpe_derive_context_test_input_data_t {
    uint32_t cert_id;
    /* If below flag is true, use previous parent handle or use derived context handle */
    bool use_parent_handle;
    bool retain_parent_context;
    bool allow_new_context_to_derive;
    bool create_certificate;
};

struct dpe_derive_context_test_data_t {
    struct dpe_derive_context_test_input_data_t inputs;
};

struct dpe_derive_context_test_params_t {
    bool is_code_hash_missing;
    bool is_config_descriptor_missing;
    bool is_authority_hash_missing;
    bool is_mode_missing;
    bool is_encoded_cbor_corrupt;
    bool is_input_dice_data_missing;
    bool is_cert_id_missing;
    bool is_retain_parent_context_missing;
    bool is_allow_new_context_to_derive_missing;
    bool is_create_certificate_missing;
    bool is_return_certificate_missing;
    bool is_allow_new_context_to_export_missing;
    bool is_export_cdi_missing;
    bool is_unsupported_params_added;
};

struct dpe_certify_key_test_params_t {
    bool is_encoded_cbor_corrupt;
    bool is_retain_context_missing;
    bool is_public_key_missing;
    bool is_label_missing;
    bool is_unsupported_params_added;
};

dpe_error_t
dpe_derive_context_with_test_param(int    context_handle,
                   uint32_t               cert_id,
                   bool                   retain_parent_context,
                   bool                   allow_new_context_to_derive,
                   bool                   create_certificate,
                   const                  DiceInputValues *dice_inputs,
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
                   struct dpe_derive_context_test_params_t *test_params);

dpe_error_t dpe_certify_key_with_test_param(int context_handle,
                    bool                    retain_context,
                    const uint8_t          *public_key,
                    size_t                  public_key_size,
                    const uint8_t          *label,
                    size_t                  label_size,
                    uint8_t                *certificate_chain_buf,
                    size_t                  certificate_chain_buf_size,
                    size_t                 *certificate_chain_actual_size,
                    uint8_t                *derived_public_key_buf,
                    size_t                  derived_public_key_buf_size,
                    size_t                 *derived_public_key_actual_size,
                    int                    *new_context_handle,
                    struct dpe_certify_key_test_params_t *test_params);

#ifdef __cplusplus
}
#endif

#endif /* __DPE_DERIVE_CONTEXT_TEST_DATA_H__ */
