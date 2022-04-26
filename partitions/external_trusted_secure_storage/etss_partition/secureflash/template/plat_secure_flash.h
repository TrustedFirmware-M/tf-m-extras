/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef _ETSS_HAL_H_
#define _ETSS_HAL_H_

#include <stdint.h>
#include <string.h>

/** Platform specific implementation of getting preprovisioned
 *  secure Flash provisioning information
 */
int32_t plat_get_secure_flash_provision_info(uint8_t *buffer, uint32_t size);

/** Platform specific implementation of storing secure Flash
 *  provisioning information
 */
int32_t plat_store_secure_flash_provision_info(uint8_t *buffer, uint32_t size);


#endif /* _ETSS_HAL_H_ */
