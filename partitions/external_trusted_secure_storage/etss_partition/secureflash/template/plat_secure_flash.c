/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include "plat_secure_flash.h"
#include "tfm_memory_utils.h"

/* Hard coded provision information only applies to developer mode */
const uint8_t stored_provision_data[] = {};

/* Platform specific implementation of getting pre-provisioned
 * secure Flash provisioning information
 */
int32_t plat_get_secure_flash_provision_info(uint8_t *buffer, uint32_t size)
{
/* TODO */
    tfm_memcpy(buffer, stored_provision_data, sizeof(stored_provision_data));
    return 0;
}

/* Platform specific implementation of storing secure Flash
 * provisioning information
 */
int32_t plat_store_secure_flash_provision_info(uint8_t *buffer, uint32_t size)
{
/* TODO */
    return 0;
}
