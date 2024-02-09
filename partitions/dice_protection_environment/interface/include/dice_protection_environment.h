/*
 * Copyright (c) 2023-2024, Arm Limited. All rights reserved.
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
#define DICE_CODE_DESCRIPTOR_MAX_SIZE       32

typedef int32_t dpe_error_t;

#define DPE_NO_ERROR                  ((dpe_error_t)0)
#define DPE_INTERNAL_ERROR            ((dpe_error_t)1)
#define DPE_INVALID_COMMAND           ((dpe_error_t)2)
#define DPE_INVALID_ARGUMENT          ((dpe_error_t)3)
#define DPE_ARGUMENT_NOT_SUPPORTED    ((dpe_error_t)4)
#define DPE_SESSION_EXHAUSTED         ((dpe_error_t)5)
#define DPE_INSUFFICIENT_MEMORY       ((dpe_error_t)128)
#define DPE_ERR_CBOR_FORMATTING       ((dpe_error_t)129)

/* Below custom configuration defines are platform dependent */
#define DPE_CERT_ID_INVALID 0
#define DPE_ROT_CERT_ID 0x100
#define DPE_CERT_ID_SAME_AS_PARENT 0xFFFFFFFF
#define DICE_CERT_SIZE  3072
#define DICE_CERT_CHAIN_SIZE  5600

/**
 * \brief Performs the DICE computation to derive a new context and optionally
 *        creates an intermediate certificate. Software component measurement
 *        must be provided in dice_inputs.
 *
 * \param[in]  context_handle              Input context handle for the DPE
 *                                         context.
 * \param[in]  cert_id                     Logical certificate id to which derived
 *                                         context belongs to.
 * \param[in]  retain_parent_context       Flag to indicate whether to retain the
 *                                         parent context. True only if a client
 *                                         will call further DPE commands on the
 *                                         same context.
 * \param[in]  allow_new_context_to_derive Flag to indicate whether derived context
 *                                         can derive further. True only if the
 *                                         new context will load further components.
 * \param[in]  create_certificate          Flag to indicate whether to create an
 *                                         intermediate certificate. True only if
 *                                         it is the last component in the layer.
 * \param[in]  dice_inputs                 DICE input values.
 * \param[in]  target_locality             Identifies the locality to which the
 *                                         derived context will be bound. Could be
 *                                         MHU id.
 * \param[in]  return_certificate          Indicates whether to return the generated
 *                                         certificate when create_certificate is true.
 * \param[in]  allow_new_context_to_export Indicates whether the DPE permits export of
 *                                         the CDI from the newly derived context.
 * \param[in]  export_cdi                  Indicates whether to export derived CDI.
 * \param[out] new_context_handle          New handle for the derived context.
 * \param[out] new_parent_context_handle   New handle for the parent context.
 * \param[out] new_certificate_buf         If create_certificate and return_certificate
 *                                         are both true, this argument holds the new
 *                                         certificate generated for the new context
 * \param[in]  new_certificate_buf_size    Size of the allocated buffer for
 *                                         new certificate.
 * \param[out] new_certificate_actual_size Actual size of the new certificate.
 * \param[out] exported_cdi_buf            If export_cdi is true, this is the
 *                                         exported CDI value.
 * \param[in]  exported_cdi_buf_size       Size of the allocated buffer for
 *                                         exported cdi.
 * \param[out] exported_cdi_actual_size    Actual size of the exported cdi.
 *
 * \return Returns error code of type dpe_error_t
 */
dpe_error_t
dpe_derive_context(int                    context_handle,
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
                   size_t                *exported_cdi_actual_size);

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

/**
 * \brief Returns the certificate chain generated for a given DPE context. The
 *        order, format, and encoding of the certificate chain are specified by
 *        a DPE profile.
 *
 * \param[in]  context_handle                  Input context handle for the DPE
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
dpe_error_t
dpe_get_certificate_chain(int      context_handle,
                          bool     retain_context,
                          bool     clear_from_context,
                          uint8_t *certificate_chain_buf,
                          size_t   certificate_chain_buf_size,
                          size_t  *certificate_chain_actual_size,
                          int     *new_context_handle);

#ifdef __cplusplus
}
#endif

#endif /* __DICE_PROTECTION_ENVIRONMENT_H__ */
