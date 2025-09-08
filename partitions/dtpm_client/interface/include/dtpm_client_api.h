/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 */

/* This file describes the TFM dTPM Client API */

#ifndef __DTPM_CLIENT_API__
#define __DTPM_CLIENT_API__

#include <stddef.h>
#include <stdint.h>

#include "psa/error.h"

#ifdef __cplusplus
extern "C" {
#endif

/* dTPM client message types that distinguish its services */
#define TFM_DTPM_CLIENT_READ        1001U
#define TFM_DTPM_CLIENT_EXTEND      1002U
#define MAX_DIGEST_SIZE             48 /* SHA384 */

struct pcr_extend_t {
    size_t hash_size;
    uint16_t hash_algo;
    uint8_t index;
    uint8_t hash[MAX_DIGEST_SIZE];
};

psa_status_t tfm_dtpm_client_extend(uint8_t index, uint16_t algo, uint8_t *hash, size_t hash_size);

#ifdef __cplusplus
}
#endif

#endif /* __DTPM_CLIENT_API__ */
