/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 */

#ifndef __RSE_BOOT_MEASUREMENT_H__
#define __RSE_BOOT_MEASUREMENT_H__

#include "measured_boot_api.h"
#include "psa/crypto_sizes.h"
#include <stddef.h>
#include <stdint.h>

#ifndef ADDITIONAL_SIGNER_MAX_AMOUNT
#define ADDITIONAL_SIGNER_MAX_AMOUNT     4U
#endif /* ADDITIONAL_SIGNER_MAX_AMOUNT */

#ifdef __cplusplus
extern "C" {
#endif

struct rse_boot_measurement_metadata_t {
    uint8_t  signer_id[SIGNER_ID_MAX_SIZE];
    size_t   signer_id_size;
    uint8_t  version[VERSION_MAX_SIZE];
    size_t   version_size;
    uint32_t measurement_algo;
    uint8_t  sw_type[SW_TYPE_MAX_SIZE];
    size_t   sw_type_size;
    uint32_t additional_signer_amount;
    struct {
        uint8_t signer_id[SIGNER_ID_MAX_SIZE];
        size_t  signer_id_size;
    } additional_signers[ADDITIONAL_SIGNER_MAX_AMOUNT];
};

struct rse_boot_measurement_value_t {
    uint8_t hash_buf[PSA_HASH_MAX_SIZE];
    uint8_t hash_buf_size;
};

struct rse_boot_measurement_t {
    struct rse_boot_measurement_value_t value;                   /* measurement value */
    struct rse_boot_measurement_metadata_t metadata;             /* metadata */
};

#ifdef __cplusplus
}
#endif

#endif /* __RSE_BOOT_MEASUREMENT_H__ */
