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

/**
 * The size of X and Y coordinate in 2 parameter style EC public
 * key. Format is as defined in [COSE (RFC 8152)]
 * (https://tools.ietf.org/html/rfc8152) and [SEC 1: Elliptic Curve
 * Cryptography](http://www.secg.org/sec1-v2.pdf).
 *
 * This size is well-known and documented in public standards.
 */
#define ECC_COORD_SIZE PSA_BITS_TO_BYTES(DPE_ATTEST_KEY_BITS)

#define MAX_ENCODED_COSE_KEY_SIZE \
    1 + /* 1 byte to encode map */ \
    2 + /* 2 bytes to encode key type */ \
    2 + /* 2 bytes to encode curve */ \
    2 * /* the X and Y coordinates + encoding */ \
        (ECC_COORD_SIZE + 1 + 2)

/**
 * \brief Encodes and signs the certificate for a context
 *
 * \param[in]  cert_ctx          Pointer to certificate context.
 * \param[out] cert_buf          Pointer to the output cert buffer.
 * \param[in]  cert_buf_size     Size of the output cert buffer.
 * \param[out] cert_actual_size  Actual size of the final certificate.
 * *
 * \return Returns error code of type dpe_error_t
 */
dpe_error_t encode_certificate(const struct cert_context_t *cert_ctx,
                               uint8_t *cert_buf,
                               size_t cert_buf_size,
                               size_t *cert_actual_size);

/**
 * \brief Stores signed certificate for a context
 *
 * \param[in] cert_ctx  Pointer to current certificate context.
 *
 * \return Returns error code of type dpe_error_t
 */
dpe_error_t store_certificate(const struct cert_context_t *cert_ctx);

/**
 * \brief Returns the encoded certificate chain from leaf certificate to the RoT
          certificate.
 *
 * \param[in]  cert_ctx                Pointer to the current leaf certificate
                                       context.
 * \param[out] cert_chain_buf          Pointer to certificate chain buffer.
 * \param[in]  cert_chain_buf_size     Size of certificate chain buffer.
 * \param[out] cert_chain_actual_size  Actual size of the chain.
 *
 * \return Returns error code of type dpe_error_t
 */
dpe_error_t get_certificate_chain(const struct cert_context_t *cert_ctx,
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

#ifdef __cplusplus
}
#endif

#endif /* __DPE_CERTIFICATE_H__ */
