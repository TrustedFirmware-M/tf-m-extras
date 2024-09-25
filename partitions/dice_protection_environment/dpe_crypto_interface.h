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

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Derives attestation key pair for a certificate.
 *
 * \param[in] cert_ctx  Pointer to current certificate context.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t derive_attestation_key(struct cert_context_t *cert_ctx);

/**
 * \brief Derives attestation CDI for a certificate
 *
 * \param[in] cert_ctx  Pointer to current certificate context.
 * \param[in] parent_cert_ctx  Pointer to parent certificate context.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t derive_attestation_cdi(struct cert_context_t *cert_ctx,
                                    const struct cert_context_t *parent_cert_ctx);
/**
 * \brief Derives seal CDI for a certificate
 *
 * \param[in] cert_ctx  Pointer to current certificate context.
 * \param[in] parent_cert_ctx  Pointer to parent certificate context.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t derive_seal_cdi(struct cert_context_t *cert_ctx,
                             const struct cert_context_t *parent_cert_ctx);

/**
 * \brief Derives certificate id from the certificate's attestation public key
 *
 * \param[in] cert_ctx  Pointer to current certificate context.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t derive_id_from_public_key(struct cert_context_t *cert_ctx);

/**
 * \brief Derives wrapping key pair for a certificate
 *
 * \param[in] cert_ctx  Pointer to current certificate context.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t derive_wrapping_key(struct cert_context_t *cert_ctx);

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
 * \brief Gets the certificate's CDI value.
 *
 * \param[in]  cert_ctx       Pointer to current certificate context.
 * \param[out] cdi_attest_buf  Buffer to hold the attestation CDI.
 * \param[in]  cdi_seal_buf    Buffer to hold the sealing CDI.
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t get_certificate_cdi_value(const struct cert_context_t *cert_ctx,
                                       uint8_t cdi_attest_buf[DICE_CDI_SIZE],
                                       uint8_t cdi_seal_buf[DICE_CDI_SIZE]);

/**
 * @brief Destroy the CDI and attestation keys for a certificate.
 *
 * \param[in] cert_ctx  Pointer to current certificate context.
 *
 */
void destroy_certificate_context_keys(const struct cert_context_t *cert_ctx);

#ifdef __cplusplus
}
#endif

#endif /* __DPE_CRYPTO_INTERFACE_H__ */
