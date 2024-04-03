/*
 * Copyright (c) 2023-2024, Arm Limited. All rights reserved.
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
 * \brief Derives attestation key pair for a layer.
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
 * \brief Derives certificate id from the layer's attestation public key
 *
 * \param[in] layer_ctx  Pointer to current layer context.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t derive_id_from_public_key(struct layer_context_t *layer_ctx);

/**
 * \brief Derives wrapping key pair for a layer
 *
 * \param[in] layer_ctx  Pointer to current layer context.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t derive_wrapping_key(struct layer_context_t *layer_ctx);

/**
 * \brief Derives CDI ID from attestation key.
 *
 * \param[in]  attest_key_id  Key ID of attestation key.
 * \param[out] cdi_id         Buffer to write the CDI ID.
 * \param[in]  cdi_id_size    Size of CDI ID to derive.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t derive_cdi_id(psa_key_id_t attest_key_id, uint8_t *cdi_id,
                           size_t cdi_id_size);

/**
 * \brief Gets the layer's CDI value.
 *
 * \param[in]  layer_ctx       Pointer to current layer context.
 * \param[out] cdi_attest_buf  Buffer to hold the attestation CDI.
 * \param[in]  cdi_seal_buf    Buffer to hold the sealing CDI.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t get_layer_cdi_value(const struct layer_context_t *layer_ctx,
                                 uint8_t cdi_attest_buf[DICE_CDI_SIZE],
                                 uint8_t cdi_seal_buf[DICE_CDI_SIZE]);
/**
 * @brief Get the RoT CDI input
 *
 * @param[out] rot_cdi_input      Buffer to contain the retrieved RoT CDI key
 * @param[in]  rot_cdi_input_size Size in bytes of the \a rot_cdi_input buffer
 *
 * @return psa_status_t
 */
psa_status_t get_rot_cdi_input(uint8_t rot_cdi_input[DICE_CDI_SIZE],
                               size_t rot_cdi_input_size);

/**
 * @brief Destroy the CDI and attestation keys for a layer.
 *
 * \param[in] layer_ctx  Pointer to current layer context.
 *
 */
void destroy_layer_keys(const struct layer_context_t *layer_ctx);

#ifdef __cplusplus
}
#endif

#endif /* __DPE_CRYPTO_INTERFACE_H__ */
