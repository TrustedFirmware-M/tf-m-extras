/*
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "rse_image_verification_api.h"
#include "rse_image_verification_defs.h"

#include "psa/client.h"
#include "psa_manifest/sid.h"


enum rse_verification_service_err_t
rse_verify_and_load_image(const uint8_t *image,
                          uint32_t image_len,

                          const struct rse_image_verification_data_t *verification_data,
                          uint32_t verification_data_len,

                          struct rse_image_verification_boot_measurement_t *boot_measurement,
                          uint32_t boot_measurement_len,
                          uint32_t *boot_measurement_size,

                          uint8_t  *destination,
                          uint32_t destination_len)
{
    psa_status_t status;

    psa_invec in_vec[] = {
        { .base = image, .len = image_len }, /* Memory-mapped IOVEC */
        { .base = verification_data, .len = verification_data_len },
    };

    psa_outvec out_vec[] = {
        { .base = boot_measurement, .len = boot_measurement_len }, /* Memory-mapped IOVEC */
        { .base = destination, .len = destination_len }, /* Memory-mapped IOVEC */
    };

    status = psa_call(TFM_RSE_IMAGE_VERIFICATION_SERVICE_HANDLE,
                      RSE_IMAGE_VERIFICATION_LOAD_IMAGE, in_vec,
                      IOVEC_LEN(in_vec), out_vec, IOVEC_LEN(out_vec));

    *boot_measurement_size = out_vec[0].len;

    return status;
}
