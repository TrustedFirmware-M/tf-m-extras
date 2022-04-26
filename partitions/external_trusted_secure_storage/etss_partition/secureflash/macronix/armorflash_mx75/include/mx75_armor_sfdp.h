/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef _MX75_ARMOR_SFDP_H
#define _MX75_ARMOR_SFDP_H

#include <string.h>
#include "tfm_memory_utils.h"
/*
 * This sfdp blob is a simulation for the SFDP database of secure Flash.
 */
const uint8_t sfdp_blob[] = {
/* SFDP Header */
//"SFDP" [31:00]
'S', 'F', 'D', 'P',
/* Minor reversion [07:00], Major reversion [15:08],
   NPH [23:16], Access Protocol [31:24]
*/
0x06, 0x01, 0x01, 0xFF, 

/* Basic Parameter Header */
/* PID LSB [07:00], PH Minor Reversion [15:08],
   PH Major Reversion [23:16], PT Size [31:24]
*/
0x00, 0x06, 0x01, 0x14,
/* PT address[23:00], PID_MSB[31:24]*/
0x18, 0x00, 0x00, 0xFF,

/* Secure Flash Parameter Header */
/* PID LSB [07:00], PH Minor Reversion [15:08],
 * PH Major Reversion [23:16], PT Size [31:24]
 */
0x14, 0x01, 0x01, 0x0F,
/* PT address[23:00], PID_MSB[31:24]*/
0x68, 0x00, 0x00, 0xFF,

/* Basic Flash Parameter Table */
0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00,

0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00,

0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00,

0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00,

0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00,

/* Secure Flash Parameter Table (sftbl) */
/* Secure Flash Type [07:00], reserved[31:08]*/
0x1F, 0x00, 0x00, 0x00, // DROWD 0

/* Cipher Suite */
/* Cipher Suite0: Key Exchange [07:00], Key Derive [15:08],
 * Encryption [23:16], Signature [31:24]
 */
0x00, 0x33, 0x03, 0x00, // DROWD 1
/* Cipher Suite0: reserved [31:00] */
0x00, 0x00, 0x00, 0x00, // DROWD 2
/* Cipher Suite1: Key Exchange [07:00], Key Derive [15:08],
 * Encryption [23:16], Signature [31:24]
 */
0x00, 0x00, 0x00, 0x00, // DROWD 3
/* Cipher Suite1: reserved [31:00] */
0x00, 0x00, 0x00, 0x00, // DROWD 4
/* Cipher Suite2: Key Exchange [07:00], Key Derive [15:08],
 * Encryption [23:16], Signature [31:24]
 */
0x00, 0x00, 0x03, 0x00, // DROWD 5
/* Cipher Suite2: reserved [31:00] */
0x00, 0x00, 0x00, 0x00, // DROWD 6
/* Cipher Suite3: Key Exchange [07:00], Key Derive [15:08],
 * Encryption [23:16], Signature [31:24]
 */
0x00, 0x00, 0x00, 0x00, // DROWD 7
/* Cipher Suite3: reserved [31:00] */
0x00, 0x00, 0x00, 0x00, // DROWD 8

/* Key Size */
/* Key Size: Session Key[23:00] <in bits>, Private Key[31:16] <in bits> */
0x00, 0x01, 0x00, 0x00, // DROWD 9
/* Key Size: Public Key[23:00] <in bits>, Preshare Key[31:16] <in bits> */
0x00, 0x00, 0x00, 0x00, // DROWD 10
/* Key Size: Salt Key[23:00] <in bits>, Root Key[31:16] <in bits> */
0x00, 0x00, 0x00, 0x00, // DROWD 11
/* Key Size: RPMC Root Key[23:00] <in bits>, RPMC Hmac Key[31:16] <in bits> */
0x00, 0x00, 0x00, 0x00, // DROWD 12

/* Architecture */
/* Number of Secure Zone [07:00],
   Size of Secure Zone[15:08] <in bytes, power of two>
*/
/* Size of Secure Read [23:16] <in bytes, power of two>,
   size of Secure Program[31:24] <in bytes, power of two>
 */
0x10, 0x12, 0x05, 0x05, // DWORD 13
/* Architecture: Size of Secure Erase0 [07:00] <in bytes, power of two>,
                 size of Secure Erase1[15:08] <in bytes, power of two>
                 Size of Secure Erase2 [23:16] <in bytes, power of two>,
                 size of Secure Erase3[31:24] <in bytes, power of two>
*/
0x0C, 0x0F, 0x10, 0x00, // DWORD 14
};

static inline int32_t _send_read_sfdp_command(uint8_t inst, uint8_t *rx_buffer,
                                              size_t rx_length,
                                              size_t addr, uint8_t addr_length,
                                              uint8_t dummy_cycles)
{
    tfm_memcpy(rx_buffer, sfdp_blob + addr, rx_length);
    return 0;
}

#endif /* _MX75_ARMOR_SFDP_H */
