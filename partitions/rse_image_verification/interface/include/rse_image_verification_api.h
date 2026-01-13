/*
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __TFM_RSE_IMAGE_VERIFICATION_H__
#define __TFM_RSE_IMAGE_VERIFICATION_H__

#include <stdint.h>
#include "psa/error.h"
#include "rse_image_verification_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Verifies, measures and loads an image to the specified destination.
 *
 *
 * @param[in]  image                     Pointer to the image buffer to verify.
 * @param[in]  image_len                 Size of the image in bytes.
 * @param[in]  verification_data         Pointer to verification data that
 *                                       will be used to verify the image.
 * @param[in]  verification_data_len     Size of the verification data buffer
 *                                       in bytes. Must be at least 4 bytes.
 * @param[out] boot_measurement          Pointer to boot measurement buffer.
 *                                       Can be NULL if there is no
 *                                       chain in the verification_data.
 * @param[in]  boot_measurement_len      Size of the boot measurement buffer
 *                                       in bytes.
 * @param[out] boot_measurement_size     Note: Currently unused because the
 *                                       rse_image_verification_boot_measurement_t
 *                                       structure size is fixed.
 * @param[out] destination               Destination where the verified image
 *                                       will be loaded.
 *                                       If equals to the image buffer, then
 *                                       the copy will be skipped, and the
 *                                       image will NOT be erased on failure.
 * @param[in]  destination_len           Size of the destination in bytes.
 *
 * @retval #RSE_VERIFICATION_SERVICE_SUCCESS
 *         Success.
 * @retval #RSE_VERIFICATION_SERVICE_ERR_INVALID_ARG
 *         The provided arguments are invalid.
 * @retval #RSE_VERIFICATION_SERVICE_ERR_VERIFICATION_FAILED
 *         The authentication was done but it failed.
 * @retval #RSE_VERIFICATION_SERVICE_ERR_BAD_KEY
 *         The provided keys in the verification data was invalid.
 * @retval #RSE_VERIFICATION_SERVICE_ERR_NV_COUNTER
 *         The NV counter check failed due to smaller counter value.
 * @retval #RSE_VERIFICATION_SERVICE_ERR_INTERNAL
 *         Internal error happened in the partition.
 * @retval #RSE_VERIFICATION_SERVICE_ERR_MEASUREMENT_FAILED
 *         An error happened during calculating or storing the measurements.
 * @retval #RSE_VERIFICATION_SERVICE_ERR_NOT_SUPPORTED
 *         The requested operation is not supported yet.
 */
enum rse_verification_service_err_t rse_verify_and_load_image(
    const uint8_t *image, uint32_t image_len,
    const struct rse_image_verification_data_t *verification_data,
    uint32_t verification_data_len,
    struct rse_image_verification_boot_measurement_t *boot_measurement,
    uint32_t boot_measurement_len, uint32_t *boot_measurement_size,
    uint8_t *destination, uint32_t destination_len);

#ifdef __cplusplus
}
#endif
#endif /* __TFM_RSE_IMAGE_VERIFICATION_H__ */
