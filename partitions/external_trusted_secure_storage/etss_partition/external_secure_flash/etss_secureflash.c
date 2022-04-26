/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <string.h>
#include "etss_secureflash.h"
#include "psa_manifest/pid.h"

static int32_t secureflash_app_id = 0;

/**
 * \brief Gets physical address of the given block ID.
 *
 * \param[in] cfg       Flash FS configuration
 * \param[in] block_id  Block ID
 * \param[in] offset    Offset position from the init of the block
 *
 * \returns Returns physical address for the given block ID.
 */
static size_t get_phys_address(const struct etss_flash_fs_config_t *cfg,
                               uint32_t block_id, size_t offset)
{
    return cfg->flash_area_addr + (block_id * cfg->block_size) + offset;
}


static etss_err_t etss_secureflash_init(
                                       const struct etss_flash_fs_config_t *cfg)
{
    secureflash_t *secureflash = (secureflash_t *)cfg->flash_dev;
    secureflash_app_id = SP_ETSS;
    if (secureflash_init(secureflash)) {
        return ETSS_ERR_STORAGE_FAILURE;
    }
    return ETSS_SUCCESS;
}

static etss_err_t etss_secureflash_read(
                                       const struct etss_flash_fs_config_t *cfg,
                                       uint32_t block_id, uint8_t *buffer,
                                       size_t offset, size_t size)
{
    secureflash_t *secureflash = (secureflash_t *)cfg->flash_dev;
    size_t addr = get_phys_address(cfg, block_id, offset);
    if (secureflash_secure_read(secureflash, buffer, addr,
                                size, secureflash_app_id)) {
        return ETSS_ERR_STORAGE_FAILURE;
    }
    return ETSS_SUCCESS;
}


static etss_err_t etss_secureflash_write(
                                       const struct etss_flash_fs_config_t *cfg,
                                       uint32_t block_id,
                                       const uint8_t *buffer,
                                       size_t offset, size_t size)
{
    secureflash_t *secureflash = (secureflash_t *)cfg->flash_dev;
    size_t addr = get_phys_address(cfg, block_id, offset);
    if (secureflash_secure_program(secureflash, buffer, addr,
                                   size, secureflash_app_id)) {
        return ETSS_ERR_STORAGE_FAILURE;
    }
    return ETSS_SUCCESS;
}

static etss_err_t etss_secureflash_flush(
                                       const struct etss_flash_fs_config_t *cfg)
{
    /* Nothing needs to be done for NOR flash, as writes are commited to flash
     * immediately.
     */
    (void)cfg;
    return ETSS_SUCCESS;
}

static etss_err_t etss_secureflash_erase(
                                       const struct etss_flash_fs_config_t *cfg,
                                       uint32_t block_id)
{
    size_t addr;
    size_t offset;
    secureflash_t *secureflash = (secureflash_t *)cfg->flash_dev;
    for (offset = 0; offset < cfg->block_size; offset += cfg->sector_size) {
        addr = get_phys_address(cfg, block_id, offset);
        if (secureflash_secure_erase(secureflash, addr,
            cfg->sector_size, secureflash_app_id)) {
            return ETSS_ERR_STORAGE_FAILURE;
        }
    }   
return ETSS_SUCCESS;
}

void etss_client_id_pass_through(int32_t client_id)
{
    secureflash_app_id = client_id;
}

const struct etss_flash_fs_ops_t etss_secure_flash_fs_ops = {
    .init = etss_secureflash_init,
    .read = etss_secureflash_read,
    .write = etss_secureflash_write,
    .flush = etss_secureflash_flush,
    .erase = etss_secureflash_erase,
};
