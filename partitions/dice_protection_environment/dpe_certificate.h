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
#include "dpe_context_mngr.h"

#ifdef __cplusplus
extern "C" {
#endif

/* As per RFC8152 */
#define DPE_CERT_LABEL_COSE_KEY_TYPE      (1)
#define DPE_CERT_LABEL_COSE_KEY_ID        (2)
#define DPE_CERT_LABEL_COSE_KEY_ALG       (3)
#define DPE_CERT_LABEL_COSE_KEY_OPS       (4)
#define DPE_CERT_LABEL_COSE_KEY_EC2_CURVE (-1)
#define DPE_CERT_LABEL_COSE_KEY_EC2_X     (-2)
#define DPE_CERT_LABEL_COSE_KEY_EC2_Y     (-3)

/* As per RFC8392 */
#define DPE_CERT_LABEL_ISSUER                    (1)
#define DPE_CERT_LABEL_SUBJECT                   (2)

/* As per Open Profile for DICE specification */
#define DPE_CERT_LABEL_RANGE_BASE                (-4670545)
#define DPE_CERT_LABEL_CODE_HASH                 (DPE_CERT_LABEL_RANGE_BASE - 0)
#define DPE_CERT_LABEL_CODE_DESCRIPTOR           (DPE_CERT_LABEL_RANGE_BASE - 1)
#define DPE_CERT_LABEL_CONFIGURATION_HASH        (DPE_CERT_LABEL_RANGE_BASE - 2)
#define DPE_CERT_LABEL_CONFIGURATION_DESCRIPTOR  (DPE_CERT_LABEL_RANGE_BASE - 3)
#define DPE_CERT_LABEL_AUTHORITY_HASH            (DPE_CERT_LABEL_RANGE_BASE - 4)
#define DPE_CERT_LABEL_AUTHORITY_DESCRIPTOR      (DPE_CERT_LABEL_RANGE_BASE - 5)
#define DPE_CERT_LABEL_MODE                      (DPE_CERT_LABEL_RANGE_BASE - 6)
#define DPE_CERT_LABEL_SUBJECT_PUBLIC_KEY        (DPE_CERT_LABEL_RANGE_BASE - 7)
#define DPE_CERT_LABEL_KEY_USAGE                 (DPE_CERT_LABEL_RANGE_BASE - 8)

/* Below labels are custom and not specified in DICE profile */
#define DPE_CERT_LABEL_SW_COMPONENTS             (DPE_CERT_LABEL_RANGE_BASE - 9)
#define DPE_CERT_LABEL_EXTERNAL_LABEL            (DPE_CERT_LABEL_RANGE_BASE - 10)
#define DPE_CERT_LABEL_CDI_EXPORT                (DPE_CERT_LABEL_RANGE_BASE - 11)
#define DPE_LABEL_CDI_ATTEST                     (1)
#define DPE_LABEL_CDI_SEAL                       (2)
#define DPE_LABEL_CERT_CHAIN                     (3)
#define DPE_LABEL_CERT                           (4)

/* Key usage constant per RFC 5280 */
#define DPE_CERT_KEY_USAGE_CERT_SIGN             (1 << 5);

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
