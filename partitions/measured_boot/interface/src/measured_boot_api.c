/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "measured_boot_api.h"
#include "measured_boot_defs.h"
#include "psa/client.h"
#include "psa_manifest/sid.h"
#include <string.h>

psa_status_t tfm_measured_boot_read_measurement(uint8_t index,
                                                uint8_t *signer_id,
                                                size_t signer_id_size,
                                                size_t *signer_id_len,
                                                uint8_t *version,
                                                size_t version_size,
                                                size_t *version_len,
                                                uint32_t *measurement_algo,
                                                uint8_t *sw_type,
                                                size_t sw_type_size,
                                                size_t *sw_type_len,
                                                uint8_t *measurement_value,
                                                size_t measurement_value_size,
                                                size_t *measurement_value_len,
                                                bool *is_locked)
{
    psa_status_t status;
    struct measured_boot_read_iovec_in_t read_iov_in = {
        .index = index,
        .sw_type_size = sw_type_size,
        .version_size = version_size,
    };

    struct measured_boot_read_iovec_out_t read_iov_out;

    psa_invec in_vec[] = {
        {.base = &read_iov_in,
         .len = sizeof(struct measured_boot_read_iovec_in_t)},
    };

    psa_outvec out_vec[] = {
        {.base = &read_iov_out,
         .len = sizeof(struct measured_boot_read_iovec_out_t)},
        {.base = signer_id, .len = signer_id_size},
        {.base = measurement_value, .len = measurement_value_size}
    };

    status = psa_call(TFM_MEASURED_BOOT_HANDLE, TFM_MEASURED_BOOT_READ,
                      in_vec, IOVEC_LEN(in_vec),
                      out_vec, IOVEC_LEN(out_vec));

    if (status == PSA_SUCCESS) {
        *is_locked = read_iov_out.is_locked;
        *measurement_algo = read_iov_out.measurement_algo;
        *sw_type_len = read_iov_out.sw_type_len;
        *version_len = read_iov_out.version_len;
        memcpy(sw_type, read_iov_out.sw_type, read_iov_out.sw_type_len);
        memcpy(version, read_iov_out.version, read_iov_out.version_len);
        *signer_id_len = out_vec[1].len;
        *measurement_value_len = out_vec[2].len;
    }

    return status;
}

psa_status_t tfm_measured_boot_extend_measurement(
                                              uint8_t index,
                                              const uint8_t *signer_id,
                                              size_t signer_id_size,
                                              const uint8_t *version,
                                              size_t version_size,
                                              uint32_t measurement_algo,
                                              const uint8_t *sw_type,
                                              size_t sw_type_size,
                                              const uint8_t *measurement_value,
                                              size_t measurement_value_size,
                                              bool lock_measurement)
{
    struct measured_boot_extend_iovec_t extend_iov = {
        .index = index,
        .lock_measurement = lock_measurement,
        .measurement_algo = measurement_algo,
        .sw_type = {0},
        .sw_type_size = sw_type_size,
    };

    psa_invec in_vec[] = {
        {.base = &extend_iov,
                            .len = sizeof(struct measured_boot_extend_iovec_t)},
        {.base = signer_id, .len = signer_id_size},
        {.base = version, .len = version_size},
        {.base = measurement_value, .len = measurement_value_size}
    };

    if (sw_type != NULL) {
        if (sw_type_size > SW_TYPE_MAX_SIZE) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        memcpy(extend_iov.sw_type, sw_type, sw_type_size);
    }

    return psa_call(TFM_MEASURED_BOOT_HANDLE,
                    TFM_MEASURED_BOOT_EXTEND,
                    in_vec, IOVEC_LEN(in_vec),
                    NULL, 0);
}
