/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 */


 #ifndef __PUBLIC_KEY_ENCODING_HELPER_H_
 #define __PUBLIC_KEY_ENCODING_HELPER_H_

 #include <stdint.h>
 #include <stdbool.h>


/*
 * This helper function is copied from the
 * tf-m-tests/tests_reg/test/secure_fw/suites/crypto/crypto_tests_common.c file.
 */

#define LEN_OFF (3) /* Offset for the Length field of the second SEQUENCE */
#define VAL_OFF (3) /* Offset for the value field of the BIT STRING */

/* This helper function gets a pointer to the bitstring associated to the publicKey
 * as encoded per RFC 5280. This function assumes that the public key encoding is not
 * bigger than 127 bytes (i.e. usually up until 384 bit curves)
 *
 * \param[in,out] p    Double pointer to a buffer containing the RFC 5280 of the ECDSA public key.
 *                     On output, the pointer is updated to point to the start of the public key
 *                     in BIT STRING form.
 * \param[in]     size Pointer to a buffer containing the size of the public key extracted
 *
 */
static inline void get_public_key_from_rfc5280_encoding(uint8_t **p, size_t *size)
{
    uint8_t *key_start = (*p) + (LEN_OFF + 1 + (*p)[LEN_OFF] + VAL_OFF);
    *p = key_start;
    *size = key_start[-2]-1; /* -2 from VAL_OFF to get the length, -1 to remove the ASN.1 padding byte count */
}

#endif /* __PUBLIC_KEY_ENCODING_HELPER_H_ */
