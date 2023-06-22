/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __DPE_CRYPTO_INTERFACE_H__
#define __DPE_CRYPTO_INTERFACE_H__

#include <stddef.h>
#include <stdint.h>
#include "dpe_context_mngr.h"
#include "psa/error.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Derives attestation key pair for a layer
 *
 * \param[in] layer_ctx  Pointer to current layer context.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t derive_attestation_key(struct layer_context_t *layer_ctx);

/**
 * \brief Creates a layer's CDI key from input.
 *
 * \param[in] layer_ctx       Pointer to layer context.
 * \param[in] cdi_input       Pointer to the input buffer.
 * \param[in] cdi_input_size  Size of the input buffer.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t create_layer_cdi_key(struct layer_context_t *layer_ctx,
                                  const uint8_t *cdi_input,
                                  size_t cdi_input_size);

/**
 * \brief Derives attestation CDI for a layer
 *
 * \param[in] layer_ctx  Pointer to current layer context.
 * \param[in] parent_layer_ctx  Pointer to parent layer context.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t derive_attestation_cdi(struct layer_context_t *layer_ctx,
                                    const struct layer_context_t *parent_layer_ctx);
/**
 * \brief Derives sealing CDI for a layer
 *
 * \param[in] layer_ctx  Pointer to current layer context.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t derive_sealing_cdi(struct layer_context_t *layer_ctx);

/**
 * \brief Derives wrapping key pair for a layer
 *
 * \param[in] layer_ctx  Pointer to current layer context.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t derive_wrapping_key(struct layer_context_t *layer_ctx);

/**
 * \brief Create and sign the certificate for a layer
 *
 * \param[in] layer_ctx  Pointer to current layer context.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t create_layer_certificate(struct layer_context_t *layer_ctx);

/**
 * \brief Stores signed certificate for a layer
 *
 * \param[in] layer_ctx  Pointer to current layer context.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t store_layer_certificate(struct layer_context_t *layer_ctx);

#ifdef __cplusplus
}
#endif

#endif /* __DPE_CRYPTO_INTERFACE_H__ */
