/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __DICE_PROTECTION_ENVIRONMENT_H__
#define __DICE_PROTECTION_ENVIRONMENT_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ext/dice/dice.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Additional defines for max size limit */
#define DICE_AUTHORITY_DESCRIPTOR_MAX_SIZE  64
#define DICE_CONFIG_DESCRIPTOR_MAX_SIZE     64
/* The theoretical maximum image version is: "255.255.65535\0" */
#define DICE_CODE_DESCRIPTOR_MAX_SIZE 14

typedef int32_t dpe_error_t;

#define DPE_NO_ERROR                  ((dpe_error_t)0)
#define DPE_INTERNAL_ERROR            ((dpe_error_t)1)
#define DPE_INVALID_COMMAND           ((dpe_error_t)2)
#define DPE_INVALID_ARGUMENT          ((dpe_error_t)3)
#define DPE_ARGUMENT_NOT_SUPPORTED    ((dpe_error_t)4)
#define DPE_SESSION_EXHAUSTED         ((dpe_error_t)5)
#define DPE_INSUFFICIENT_MEMORY       ((dpe_error_t)128)

/**
 * \brief Performs the DICE computation to derive a child context and optionally
 *        creates an intermediate certificate. Software component measurement
 *        must be provided in dice_inputs.
 *
 * \param[in]  context_handle             Input context handle for the DPE
 *                                        context.
 * \param[in]  retain_parent_context      Flag to indicate whether to retain the
 *                                        parent context. True only if a client
 *                                        will call further DPE commands on the
 *                                        same context.
 * \param[in]  allow_child_to_derive      Flag to indicate whether child context
 *                                        can derive further. True only if the
 *                                        child will load further components.
 * \param[in]  create_certificate         Flag to indicate whether to create an
 *                                        intermediate certificate. True only if
 *                                        it is the last component in the layer.
 * \param[in]  dice_inputs                DICE input values.
 * \param[out] new_child_context_handle   New handle for the child context.
 * \param[out] new_parent_context_handle  New handle for the parent context.
 *
 * \return Returns error code of type dpe_error_t
 */
dpe_error_t
dpe_derive_child(int                    context_handle,
                 bool                   retain_parent_context,
                 bool                   allow_child_to_derive,
                 bool                   create_certificate,
                 const DiceInputValues *dice_inputs,
                 int                   *new_child_context_handle,
                 int                   *new_parent_context_handle);

/**
 * \brief Destroys a DPE context.
 *
 * \param[in] context_handle       Input context handle for the DPE context to
 *                                 be destroyed.
 * \param[in] destroy_recursively  Flag to indicate whether all derived contexts
 *                                 should also be destroyed recursively.
 *
 * \return Returns error code of type dpe_error_t
 */
dpe_error_t
dpe_destroy_context(int context_handle,
                    bool destroy_recursively);

/**
 * \brief Certifies an attestation key with a new leaf certificate and returns
 *        the certificate chain containing all certificates up to and including
 *        the new leaf certificate.
 *
 * \param[in]  context_handle                  Input context handle for the DPE
 *                                             context.
 * \param[in]  retain_context                  Flag to indicate whether to
 *                                             retain the context.
 * \param[in]  public_key                      Public key to certify, or NULL to
 *                                             derive it from the context and
 *                                             the label argument.
 * \param[in]  public_key_size                 Size of the public key input.
 * \param[in]  label                           Label to use in the key
 *                                             derivation if public key is not
 *                                             provided.
 * \param[in]  label_size                      Size of the label input.
 * \param[out] certificate_chain_buf           Buffer to write the certificate
 *                                             chain output.
 * \param[in]  certificate_chain_buf_size      Size of the certificate chain
 *                                             buffer.
 * \param[out] certificate_chain_actual_size   Size of the certificate chain
 *                                             output written to the buffer.
 * \param[out] derived_public_key_buf          Buffer to write the derived
 *                                             public key.
 * \param[in]  derived_public_key_buf_size     Size of the public key buffer.
 * \param[out] derived_public_key_actual_size  Size of the public key written to
 *                                             the buffer.
 * \param[out] new_context_handle              New handle for the DPE context.
 *
 * \return Returns error code of type dpe_error_t
 */
dpe_error_t
dpe_certify_key(int            context_handle,
                bool           retain_context,
                const uint8_t *public_key,
                size_t         public_key_size,
                const uint8_t *label,
                size_t         label_size,
                uint8_t       *certificate_chain_buf,
                size_t         certificate_chain_buf_size,
                size_t        *certificate_chain_actual_size,
                uint8_t       *derived_public_key_buf,
                size_t         derived_public_key_buf_size,
                size_t        *derived_public_key_actual_size,
                int           *new_context_handle);

#ifdef __cplusplus
}
#endif

#endif /* __DICE_PROTECTION_ENVIRONMENT_H__ */
