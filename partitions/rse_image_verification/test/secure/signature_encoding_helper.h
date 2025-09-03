/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 */


#ifndef __SIGNATURE_ENCODING_HELPER_H_
#define __SIGNATURE_ENCODING_HELPER_H_

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This helper function is copied from the
 * tf-m-tests/tests_reg/test/secure_fw/suites/crypto/crypto_tests_common.c file.
 */

/**
 * @brief This helper function parses the DER encoding of a ASN.1 specified
 *        ECDSA signature as described by RFC 5480 into a buffer as raw bytes
 *        of the (r,s) integer pair
 *
 * @note  This helper function assumes that the length field of the TLV types
 *        involved is never greater than 127, i.e. the MSB of the length byte
 *        is never set, which is the case for signatures generated up to the
 *        P384 curve. For longer curves, this needs to be revisited.
 *
 * @note  This function considers an encoding as valid even if it contains only
 *        the first integer. It then sets the second integer as zero.
 *
 * @param[in] sig          Buffer containing the ASN.1 DER encoded signature
 * @param[in] sig_len      Size in bytes of the buffer pointed by \a sig
 * @param[out] r_s_pair    Buffer to contain the raw bytes of the (r,s) pair
 * @param[in] r_s_pair_len Size in bytes of the \a r_s_pair buffer. It must
 *                         account for the maximum possible value, i.e. in
 *                         a P384 curve it must 48 * 2 bytes long
 *
 * @return true   The ASN.1 encoding is valid and follows the specification
 * @return false  The ASN.1 encoding is not valid or does not follow the spec
 */
static inline bool parse_signature_from_rfc5480_encoding(const uint8_t *sig,
                                                  size_t sig_len,
                                                  uint8_t *r_s_pair,
                                                  size_t r_s_pair_len)
{
    const uint8_t *start = NULL;
    size_t len_to_copy = 0;

    memset(r_s_pair, 0, r_s_pair_len);

    start = &sig[4];
    len_to_copy = sig[3];
    if ( (sig[5] & 0x80) && (sig[4] == 0x00) ) {
        len_to_copy--; /* Discard the initial 0x00 */
        start++;
    }

    memcpy(&r_s_pair[r_s_pair_len/2 - len_to_copy], start, len_to_copy);

    if (4 + sig[3] == sig_len) {
        /* This encoding has only one integer, just set the other to zero */
        return true;
    }

    start = &sig[3 + sig[3] + 3];
    len_to_copy = sig[3 + sig[3] + 2];
    if ( (sig[3 + sig[3] + 4] & 0x80) && (sig[3 + sig[3] + 3] == 0x00) ) {
        len_to_copy--;
        start++;
    }

    memcpy(&r_s_pair[r_s_pair_len - len_to_copy], start, len_to_copy);

    return true;
}

#ifdef __cplusplus
}
#endif
#endif /* __SIGNATURE_ENCODING_HELPER_H_ */
