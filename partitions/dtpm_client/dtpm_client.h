/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 */

#ifndef __DTPM_CLIENT_H__
#define __DTPM_CLIENT_H__

#include <stddef.h>
#include <stdint.h>

#include "psa/error.h"
#include "tpm_client/tpm2.h"

#include "measured_boot_api.h"

#ifdef __cplusplus
extern "C" {
#endif

psa_status_t dtpm_client_extend(uint8_t pcr_index, uint8_t *value, uint16_t hash_alg, size_t hash_size);

psa_status_t get_event_log(uint8_t *buffer, size_t buffer_size, size_t *event_log_size);

#ifdef __cplusplus
}
#endif

#endif /* __DTPM_CLIENT_H__ */
