/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __DPE_CONTEXT_MNGR_H__
#define __DPE_CONTEXT_MNGR_H__

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "dice_protection_environment.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DICE_WRAPPING_KEY_SIZE  32
#define DICE_CERT_SIZE  1024

#define INVALID_HANDLE 0xFFFFFFFF
#define INVALID_COMPONENT_IDX 0xFFFF
#define INVALID_NONCE_VALUE  0xFFFF
#define MAX_NUM_OF_COMPONENTS 30
#define DPE_ROT_LAYER_IDX 0
#define MAX_NUM_OF_LAYERS 10
#define INVALID_LAYER_IDX 65535

/* Most significant 16 bits represent nonce & remaining 16 bits represent component index */
#define GET_IDX(handle) ((handle) & 0xffff)
#define GET_NONCE(handle) ((handle >> 16) & 0xffff)

#define SET_IDX(handle, idx) ((handle & 0xffff0000) | idx)
#define SET_NONCE(handle, nonce) ((handle & 0x00ffff) | (nonce << 16))

struct component_context_data_t {
    uint8_t        measurement_value[DICE_HASH_SIZE];
    uint8_t        measurement_descriptor[DICE_CODE_DESCRIPTOR_MAX_SIZE];
    size_t         measurement_descriptor_size;
    uint8_t        signer_id[DICE_HASH_SIZE];
    uint8_t        signer_id_descriptor[DICE_AUTHORITY_DESCRIPTOR_MAX_SIZE];
    size_t         signer_id_descriptor_size;
    uint8_t        config_value[DICE_INLINE_CONFIG_SIZE];
    uint8_t        config_descriptor[DICE_CONFIG_DESCRIPTOR_MAX_SIZE];
    size_t         config_descriptor_size;
    DiceMode       mode;
    uint8_t        hidden[DICE_HIDDEN_SIZE];
};

struct component_context_t {
    struct component_context_data_t data;   /* Component context data */
    bool in_use;                            /* Flag to indicate if element is used */
    bool is_leaf;                           /* Is the component allowed to derive */
    uint16_t nonce;                         /* Context handle nonce for the component */
    uint16_t parent_idx;                    /* Parent component's index */
    uint16_t linked_layer_idx;              /* Layer component is linked to */
    uint32_t expected_mhu_id;               /* Expected mhu to authorise derivation */
};

struct layer_context_data_t {
    uint8_t cdi_attest[DICE_CDI_SIZE];
    uint8_t cdi_seal[DICE_CDI_SIZE];
    uint8_t wrapping_key[DICE_WRAPPING_KEY_SIZE];
    uint8_t cert_buf[DICE_CERT_SIZE];
    size_t cert_buf_size;
};

enum layer_state_t {
    LAYER_STATE_CLOSED = 0,
    LAYER_STATE_OPEN,
    LAYER_STATE_FINALISED
};

struct layer_context_t {
    struct layer_context_data_t data;
    uint16_t parent_layer_idx;
    enum layer_state_t state;
};

/**
 * \brief Derives a root of trust component context and creates certificate.
 *
 * \param[in]  dice_inputs               Pointer to dice_input buffer.
 * \param[out] new_child_context_handle  A new handle for child context.
 * \param[out] new_parent_context_handle A new handle for parent context.
 *
 * \return Returns error code of type dpe_error_t
 */
dpe_error_t derive_rot_context(const DiceInputValues *dice_inputs,
                               int *new_child_ctx_handle,
                               int *new_parent_ctx_handle);

/**
 * \brief Derives a child component context and optionally creates certificate
 *        chain.
 *
 * \param[in]  input_context_handle      Input handle to child component context
 * \param[in]  retain_parent_context     Flag to indicate if parent context need
 *                                       to be retained. TRUE only if a client
 *                                       is calling DPE commands multiple times
 * \param[in]  allow_child_to_derive     Flag to indicate if requested child can
 *                                       derive further.
 * \param[in]  create_certificate        Flag to indicate if certificate needs
 *                                       to be created. TRUE only if it is the
 *                                       last component in the layer.
 * \param[in]  dice_inputs               Pointer to dice_input buffer.
 * \param[in]  client_id                 Identifier of the client calling the
 *                                       service.
 * \param[out] new_child_context_handle  A new handle for child context.
 * \param[out] new_parent_context_handle A new handle for parent context.
 *
 * \return Returns error code of type dpe_error_t
 */
dpe_error_t derive_child_request(int input_context_handle,
                                 bool retain_parent_context,
                                 bool allow_child_to_derive,
                                 bool create_certificate,
                                 const DiceInputValues *dice_inputs,
                                 int32_t client_id,
                                 int *new_child_context_handle,
                                 int *new_parent_context_handle);

/**
 * \brief Initialise all DPE Layer and component contexts
 *
 */
void initialise_all_dpe_contexts(void);

#ifdef __cplusplus
}
#endif

#endif /* __DPE_CONTEXT_MNGR_H__ */
