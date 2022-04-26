/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef _ETSS_SECURE_FLASH_H_
#define _ETSS_SECURE_FLASH_H_

#include <stdint.h>
#include "secureflash.h"
#include "../secureflash_fs/etss_flash_fs.h"
#include "etss_defs.h"


#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file etss_secureflash.h
 *
 * \brief This file describes secure Flash filesystem operations
 *
 */

#define ETSS_FLASH_ALIGNMENT   SECURE_FLASH_PROGRAM_UNIT
void etss_client_id_pass_through(int32_t client_id);
extern const struct etss_flash_fs_ops_t etss_secure_flash_fs_ops;

#ifdef __cplusplus
}
#endif
#endif /* _ETSS_SECURE_FLASH_H_ */
