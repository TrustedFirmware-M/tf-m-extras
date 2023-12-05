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
#include "dpe_crypto_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DICE_CERT_SIZE  3072
#define DICE_CERT_CHAIN_SIZE  3200
/* Below encoded CDI size accomodate both Attest and Seal CDI */
#define DICE_MAX_ENCODED_CDI_SIZE ((2 * DICE_CDI_SIZE) + 16)

#define INVALID_HANDLE 0xFFFFFFFF
#define INVALID_COMPONENT_IDX 0xFFFF
#define INVALID_NONCE_VALUE  0xFFFF
#define INVALID_LAYER_IDX 65535
#define DPE_ROT_LAYER_IDX 0

/* Below configuration defines are platform dependant */
#define MAX_NUM_OF_COMPONENTS 30
#define MAX_NUM_OF_LAYERS 6
#define DPE_PLATFORM_LAYER_IDX 1
#define DPE_SECURE_WORLD_AND_HYPERVISOR_LAYER_IDX 2
/* Below threshold defines the threshold below which a context cannot be destroyed */
#define DPE_DESTROY_CONTEXT_THRESHOLD_LAYER_IDX DPE_SECURE_WORLD_AND_HYPERVISOR_LAYER_IDX

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
    bool is_allowed_to_derive;              /* Is the component allowed to derive */
    bool is_export_cdi_allowed;             /* Is CDI allowed to export */
    uint16_t nonce;                         /* Context handle nonce for the component */
    uint16_t parent_idx;                    /* Parent component's index */
    uint16_t linked_layer_idx;              /* Layer component is linked to */
    int32_t  target_locality;               /* Identifies the locality to which the
                                             * derived context will be bound */
    uint32_t expected_mhu_id;               /* Expected mhu to authorise derivation */
};

struct layer_context_data_t {
    psa_key_id_t cdi_key_id;
    uint8_t cdi_seal[DICE_CDI_SIZE];
    uint8_t cdi_id[DICE_ID_SIZE];
    psa_key_id_t attest_key_id;
    uint8_t attest_pub_key[DPE_ATTEST_PUB_KEY_SIZE];
    size_t attest_pub_key_len;
    uint8_t attest_key_label[DPE_EXTERNAL_LABEL_MAX_SIZE];
    size_t attest_key_label_len;
    uint8_t cert_buf[DICE_CERT_SIZE];
    size_t cert_buf_len;
};

enum layer_state_t {
    LAYER_STATE_CLOSED = 0,
    LAYER_STATE_OPEN,
    LAYER_STATE_FINALISED
};

struct layer_context_t {
    struct layer_context_data_t data;
    uint16_t parent_layer_idx;
    uint8_t attest_cdi_hash_input[DPE_HASH_ALG_SIZE];
    enum layer_state_t state;
    bool is_external_pub_key_provided;
    bool is_cdi_to_be_exported;
};

/**
 * \brief Initialise the DPE context manager.
 *
 * \param[out] rot_ctx_handle  A new context handle for the RoT context.
 *
 * \return Returns error code of type dpe_error_t
 */
dpe_error_t initialise_context_mngr(int *rot_ctx_handle);

/**
 * \brief Derives a component context and optionally creates certificate
 *        chain.
 *
 * \param[in]  input_context_handle        Input handle to parent component context.
 * \param[in]  retain_parent_context       Flag to indicate if parent context need
 *                                         to be retained. TRUE only if a client
 *                                         is calling DPE commands multiple times.
 * \param[in]  allow_new_context_to_derive Flag to indicate if derived context can
 *                                         derive further.
 * \param[in]  create_certificate          Flag to indicate if certificate needs
 *                                         to be created. TRUE only if it is the
 *                                         last component in the layer.
 * \param[in]  dice_inputs                 Pointer to dice_input buffer.
 * \param[in]  client_id                   Identifier of the client calling the
 *                                         service.
 * \param[in]  target_locality             Identifier of the locality to which the
 *                                         derived context should be bound to.
 * \param[in]  return_certificate          Indicates whether to return the generated
 *                                         certificate when create_certificate is true.
 * \param[in]  allow_new_context_to_export Indicates whether the DPE permits export of
 *                                         the CDI from the newly derived context.
 * \param[in]  export_cdi                  Indicates whether to export derived CDI.
 * \param[out] new_context_handle          A new handle for derived context.
 * \param[out] new_parent_context_handle   A new handle for parent context.
 * \param[out] new_certificate_buf         If create_certificate and return_certificate
 *                                         are both true, this argument holds the new
 *                                         certificate generated for the new context.
 * \param[in]  new_certificate_buf_size    Size of the allocated buffer for
 *                                         new certificate.
 * \param[out] new_certificate_actual_size Actual size of the new certificate.
 * \param[out] exported_cdi_buf            If export_cdi is true, this is the
 *                                         exported CDI value.
 * \param[in]  exported_cdi_buf_size       Size of the allocated buffer for
 *                                         exported CDI.
 * \param[out] exported_cdi_actual_size    Actual size of the exported CDI.
 *
 * \return Returns error code of type dpe_error_t
 */
dpe_error_t derive_context_request(int input_ctx_handle,
                                   bool retain_parent_context,
                                   bool allow_new_context_to_derive,
                                   bool create_certificate,
                                   const DiceInputValues *dice_inputs,
                                   int32_t client_id,
                                   int32_t target_locality,
                                   bool return_certificate,
                                   bool allow_new_context_to_export,
                                   bool export_cdi,
                                   int *new_context_handle,
                                   int *new_parent_context_handle,
                                   uint8_t *new_certificate_buf,
                                   size_t new_certificate_buf_size,
                                   size_t *new_certificate_actual_size,
                                   uint8_t *exported_cdi_buf,
                                   size_t exported_cdi_buf_size,
                                   size_t *exported_cdi_actual_size);

/**
 * \brief Destroys a component context and optionally depending on argument
 *        destroy_recursively, destroys all its child context too.
 *
 * \param[in]  input_context_handle      Input handle to child component context
 * \param[in]  destroy_recursively       Flag to indicate if all derived contexts
 *                                       should also be destroyed recursively.
 *
 * \return Returns error code of type dpe_error_t
 */
dpe_error_t destroy_context_request(int input_ctx_handle,
                                    bool destroy_recursively);

/**
 * \brief  Function to get the pointer to a component context if linked to a layer
 *
 * \param[in] layer_idx      Index of the linked layer
 * \param[in] component_idx  Index of the component context in the array
 *
 * \return Returns pointer to the component context if it is linked to the input
 *         layer else returns NULL
 */
struct component_context_t* get_component_if_linked_to_layer(uint16_t layer_idx,
                                                             uint16_t component_idx);

/**
 * \brief  Function to get the pointer to a layer context
 *
 * \param[in] layer_idx      Index of the layer in the layer context array
 *                           for which pointer is required
 *
 * \return Returns pointer to the layer context if input index is valid
 *         else returns NULL
 */
struct layer_context_t* get_layer_ctx_ptr(uint16_t layer_idx);

/**
 * \brief Generates a leaf certificate and returns all the certificate chain
 *        leading to it. This command functionality depends on whether:
 *        - last layer is finalised
 *        - public key is supplied to the command
 *        - label is supplied to the command
 *
 *  +---------------+------------+------------+----------------+
 *  |               | pub_key    | no pub_key |                |
 *  +---------------+------------+------------+----------------+
 *  |               |            | see Note C | label          |
 *  | finalized     + see Note A +------------+----------------+
 *  |               |            | see Note D | no label       |
 *  +---------------+------------+------------+----------------+
 *  |               |            | see Note E | label          |
 *  | not finalized + see Note B +------------+----------------+
 *  |               |            | see Note F | no label       |
 *  +---------------+------------+------------+----------------+
 *
 *  A - Opens a new layer (if not opened), creates a leaf certificate which
 *      includes supplied key and generates certificate chain.
 *  B - Creates certificate for current (existing) layer, which includes supplied
 *      key and generates certificate chain.
 *  C - Opens a new layer (if not opened), performs derivation which includes
 *      supplied label, creates leaf certificate (including supplied label as a
 *      claim) and generates certificate chain.
 *  D - Opens a new layer (if not opened), performs standard derivation,
 *      creates a leaf certificate and generates certificate chain.
 *  E - Performs derivation (which includes supplied label) for current/existing layer,
 *      creates certificate which includes supplied label as a claim, and generates
 *      certificate chain.
 *  F - Performs standard derivation for current/existing layer, creates certificate
 *      and generates certificate chain.
 *
 * \param[in]  input_ctx_handle                Input handle to component context.
 * \param[in]  retain_context                  Flag to indicate if context needs
 *                                             to be retained. TRUE only if a client
 *                                             is calling DPE commands multiple times.
 * \param[in]  public_key                      The public key to certify. If omitted,
 *                                             key pair is deterministically derived
 *                                             from the context and label argument.
 * \param[in]  public_key_size                 Size of the input public key.
 * \param[in]  label                           Additional input to the key derivation
 *                                             from the context. If public key is
 *                                             already provided, this argument is
 *                                             ignored.
 * \param[in]  label_size                      Size of the input label.
 * \param[out] certificate_chain_buf           Pointer to the buffer where
 *                                             certificate chain will be stored.
 * \param[in]  certificate_chain_buf_size      Size of the allocated buffer for
 *                                             certificate chain.
 * \param[out] certificate_chain_actual_size   Actual size of the certificate
 *                                             chain.
 * \param[out] derived_public_key_buf          Pointer to the buffer where
 *                                             derived public key will be stored.
 * \param[in]  derived_public_key_buf_size     Size of the allocated buffer for
 *                                             derived public key.
 * \param[out] derived_public_key_actual_size  Actual size of the derived public
 *                                             key.
 * \param[out] new_context_handle              A renewed handle for same context.
 *
 * \return Returns error code of type dpe_error_t
 */
dpe_error_t certify_key_request(int input_ctx_handle,
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
                                int *new_context_handle);

/**
 * \brief Returns the certificate chain generated for a given DPE context. The
 *        order, format, and encoding of the certificate chain are specified by
 *        a DPE profile.
 *
 * \param[in]  input_ctx_handle                Input context handle for the DPE
 *                                             context.
 * \param[in]  retain_context                  Flag to indicate whether to
 *                                             retain the context.
 * \param[in]  clear_from_context              Flag to indicate whether DPE must
 *                                             clear the certificate chain from
 *                                             the context so subsequent calls
 *                                             on a given context, or contexts
 *                                             derived from it do not include
 *                                             the certificates returned by this
 *                                             command.
 *                                             retain the context.
 * \param[out] certificate_chain_buf           Buffer to write the certificate
 *                                             chain output.
 * \param[in]  certificate_chain_buf_size      Size of the certificate chain
 *                                             buffer.
 * \param[out] certificate_chain_actual_size   Size of the certificate chain
 *                                             output written to the buffer.
 * \param[out] new_context_handle              New handle for the DPE context.
 *
 * \return Returns error code of type dpe_error_t
 */
dpe_error_t get_certificate_chain_request(int input_ctx_handle,
                                          bool retain_context,
                                          bool clear_from_context,
                                          uint8_t *certificate_chain_buf,
                                          size_t certificate_chain_buf_size,
                                          size_t *certificate_chain_actual_size,
                                          int *new_context_handle);
#ifdef __cplusplus
}
#endif

#endif /* __DPE_CONTEXT_MNGR_H__ */
