/*
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __DTPM_CLIENT_PARTITION_HAL_H__
#define __DTPM_CLIENT_PARTITION_HAL_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "stdint.h"
#include "event_record.h"

#include "tfm_plat_defs.h"
#include "tpm_platform.h"

#include "psa/crypto.h"

#define MAX_SECURITY_CONFIG_NAME_LEN 32
#define MAX_SECURITY_CONFIG_DATA_LEN 32

#define INSECURE_LIFECYCLE_EVENT_ID 0x0
#define DEBUG_EVENT_ID 0x1

struct security_config_data {   /* The digest is calculated over the structure. */
    uint64_t name_length;
    uint64_t data_length;
    char     name[MAX_SECURITY_CONFIG_NAME_LEN];
    int8_t   config_data[MAX_SECURITY_CONFIG_DATA_LEN];
};

struct security_config {
    struct security_config_data security_config_data;
    event_log_metadata_t event_log_metadata;
    psa_algorithm_t hash_type;
    uint8_t pcr_index;
};

/**
 * \brief   Retrieve the platform security configuration data.
 *
 *          This function copies the current security configuration
 *          into the provided buffer and reports the number of bytes
 *          written.
 *
 * \param[out] security_config         Double pointer to a buffer to receive the security configuration.
 * \param[out] security_config_len     Pointer to variable that on return holds the number of elements
 *                                     in security_config array.
 *
 * \return  Returns values as specified by the \ref tfm_plat_err_t
 */
enum tfm_plat_err_t tfm_plat_get_security_config_data(struct security_config **security_config,
                                                      size_t *security_config_len);

/**
 * \brief Get platform configuration for a TPM instance.
 *
 * Retrieves the timeout operations and SPI platform configuration associated
 * with the requested TPM instance. This can be invoked before calling
 * tpm_interface_init() to query platform-specific settings.
 *
 * \param[out] timeout_ops     Pointer to store timeout operation callbacks.
 * \param[out] spi_plat        Double pointer to address of SPI platform configuration.
 * \param[in]  tpm_instance_id TPM instance number to query.
 *
 * \return 0 on success; a negative value if the TPM instance is out of range.
 */
int tpm_plat_get_tpm_platform_config(struct tpm_timeout_ops *timeout_ops,
                                    const struct tpm_spi_plat **spi_plat,
                                    uint8_t tpm_instance_id);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __DTPM_CLIENT_PARTITION_HAL_H__ */
