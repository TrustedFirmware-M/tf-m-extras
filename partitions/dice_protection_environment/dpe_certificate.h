/*
 * Copyright (c) 2023-2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __DPE_CERTIFICATE_H__
#define __DPE_CERTIFICATE_H__

#include <stddef.h>
#include <stdint.h>
#include "dpe_certificate_common.h"
#include "dpe_context_mngr.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DICE_MAX_ENCODED_PUBLIC_KEY_SIZE         (DPE_ATTEST_PUB_KEY_SIZE + 32)

/**
 * \brief Encodes and signs the certificate for a layer
 *
 * \param[in] layer_idx         Index of the current layer context.
 * \param[in] layer_ctx         Pointer to current layer context.
 * \param[in] parent_layer_ctx  Pointer to parent layer context.
 *
 * \return Returns error code of type dpe_error_t
 */
dpe_error_t encode_layer_certificate(uint16_t layer_idx,
                                     struct layer_context_t *layer_ctx,
                                     const struct layer_context_t *parent_layer_ctx);

/**
 * \brief Stores signed certificate for a layer
 *
 * \param[in] layer_ctx  Pointer to current layer context.
 *
 * \return Returns error code of type dpe_error_t
 */
dpe_error_t store_layer_certificate(struct layer_context_t *layer_ctx);

/**
 * \brief Returns the encoded certificate chain from leaf layer to the RoT layer.
 *
 * \param[in]  layer_idx               Index of the current leaf layer context.
 * \param[out] cert_chain_buf          Pointer to certificate chain buffer.
 * \param[in]  cert_chain_buf_size     Size of certificate chain buffer.
 * \param[out] cert_chain_actual_size  Actual size of the chain.
 *
 * \return Returns error code of type dpe_error_t
 */
dpe_error_t get_certificate_chain(uint16_t layer_idx,
                                  uint8_t *cert_chain_buf,
                                  size_t cert_chain_buf_size,
                                  size_t *cert_chain_actual_size);

/**
 * \brief Returns the encoded CDI from raw value.
 *
 * \param[in]  cdi_attest_buf            Buffer holds the  attestation CDI data.
 * \param[in]  cdi_seal_buf              Buffer holds the  sealing CDI data.
 * \param[out] encoded_cdi_buf           Pointer to the output encoded CDI buffer.
 * \param[in]  encoded_cdi_buf_size      Size of the encoded CDI buffer.
 * \param[out] exported_cdi_actual_size  Actual size of the encoded CDI.
 *
 * \return Returns error code of type dpe_error_t
 */
dpe_error_t encode_cdi(const uint8_t cdi_attest_buf[DICE_CDI_SIZE],
                       const uint8_t cdi_seal_buf[DICE_CDI_SIZE],
                       uint8_t *encoded_cdi_buf,
                       size_t encoded_cdi_buf_size,
                       size_t *encoded_cdi_actual_size);

/**
 * \brief Clears the certificate chain.
 *
 * \param[in] layer_idx  Index of the current layer context.
 * \param[in] layer_ctx  Pointer to current layer context.
 *
 */
void clear_certificate_chain(uint16_t layer_idx,
                             struct layer_context_t *layer_ctx);

/**
 * \brief Adds already encoded certificate to the array.
 *
 * \param[in]  cert_buf                  Pointer to the input cert buffer.
 * \param[in]  cert_buf_size             Size of the input cert buffer.
 * \param[out] encoded_cert_buf          Pointer to the output encoded cert buffer.
 * \param[in]  encoded_cert_buf_size     Size of the encoded cert buffer.
 * \param[out] encoded_cert_actual_size  Actual size of the encoded cert byte array.
 *
 * \return Returns error code of type dpe_error_t
 */
dpe_error_t add_encoded_layer_certificate(const uint8_t *cert_buf,
                                          size_t cert_buf_size,
                                          uint8_t *encoded_cert_buf,
                                          size_t encoded_cert_buf_size,
                                          size_t *encoded_cert_actual_size);

#ifdef __cplusplus
}
#endif

#endif /* __DPE_CERTIFICATE_H__ */
