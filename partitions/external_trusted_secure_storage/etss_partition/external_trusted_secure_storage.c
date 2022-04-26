/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include "external_trusted_secure_storage.h"
#include "etss_req_mngr.h"
#include "psa_manifest/pid.h"
#include "tfm_memory_utils.h"
#include "etss_utils.h"
#include "external_secure_flash/etss_secureflash.h"
#include "secureflash_fs/etss_flash_fs.h"
#include "secureflash_error.h"


#ifndef ETSS_BUF_SIZE
/* By default, set the ETSS buffer size to the max asset size so that all
 * requests can be handled in one iteration.
 * ETSS_MAX_ASSET_SIZE is defined in etss_config.cmake
 */
#define ETSS_BUF_SIZE ETSS_MAX_ASSET_SIZE
#endif

#ifndef ETSS_FILE_ID_SIZE
#define ETSS_FILE_ID_SIZE 12
#endif
#ifndef ETSS_DEFAULT_EMPTY_BUFF_VAL
#define ETSS_DEFAULT_EMPTY_BUFF_VAL 0
#endif

/* If secure Flash has several security regions which can be configured with
 * independent security policy and access permission,then it caters to etss
 * multi-client isolation. The allocated security region of each application id
 * (client id) should be indicated in secureflash_layout.h of each secure Flash.
 */
#if defined(MULTI_CLIENT_ISOLATION)
#define SECURE_FLASH_CLIENT_ID(x)    SECURE_FLASH_CLIENT##x##_ID
#define SECURE_FLASH_CLIENT_AREA_START_ADDR(x)    \
                                     SECURE_FLASH_CLIENT##x##_AREA_START_ADDR
#define SECURE_FLASH_CLIENT_AREA_SIZE(x)          \
                                     SECURE_FLASH_CLIENT##x##_AREA_SIZE
#define SECURE_FLASH_CLIENT_SECTORS_PER_BLOCK(x)  \
                                     SECURE_FLASH_CLIENT##x##_SECTORS_PER_BLOCK
#endif
/* Buffer to store asset data from the caller.
 * Note: size must be aligned to the max flash program unit to meet the
 * alignment requirement of the filesystem.
 */
static uint8_t asset_data[ETSS_UTILS_ALIGN(ETSS_BUF_SIZE,
                                           ETSS_FLASH_ALIGNMENT)];
static uint8_t g_fid[ETSS_FILE_ID_SIZE];

#if defined(MULTI_CLIENT_ISOLATION)
    typedef struct etss_fs_ctx_info {
        int32_t client_id;
        etss_flash_fs_ctx_t fs_ctx;
    }etss_fs_ctx_info_t;
    static struct etss_flash_fs_config_t fs_cfg_etss[SECURE_FLASH_CLIENT_NUM] = {0};
    static etss_fs_ctx_info_t etss_fs_ctx_tbl[SECURE_FLASH_CLIENT_NUM] = {0};
    static etss_flash_fs_ctx_t *fs_ctx_etss_ptr;
#else
    static etss_flash_fs_ctx_t fs_ctx_etss;
    static etss_flash_fs_ctx_t *fs_ctx_etss_ptr = &fs_ctx_etss;
#endif
static struct etss_file_info_t g_file_info;


vendor_op_register_t secureflash_vendor_impl = {
    .sf_name = SECURE_FLASH_NAME,
    .vendor_op_register = SECURE_FLASH_VENDOR_OP_REGISTER,
};
secureflash_t secureflash = {
    ._init_ref_count = 0,
    ._is_initialized = false,
    .vendor_op_register = &secureflash_vendor_impl,
};

static struct etss_flash_fs_config_t fs_cfg_etss_common = {
    .flash_dev = &secureflash,
    .program_unit = ETSS_FLASH_ALIGNMENT,
    .max_file_size = ETSS_UTILS_ALIGN(ETSS_MAX_ASSET_SIZE, ETSS_FLASH_ALIGNMENT),
    .max_num_files = ETSS_NUM_ASSETS + 1, /* Extra file for atomic replacement */
};
/**
 * \brief Maps a pair of client id and uid to a file id.
 *
 * \param[in]  client_id  Identifier of the asset's owner (client)
 * \param[in]  uid        Identifier for the data
 * \param[out] fid        Identifier of the file
 */
static void etss_get_fid(int32_t client_id,
                         psa_storage_uid_t uid,
                         uint8_t *fid)
{
    tfm_memcpy(fid, (const void *)&client_id, sizeof(client_id));
    tfm_memcpy(fid + sizeof(client_id), (const void *)&uid, sizeof(uid));
}

#if defined(MULTI_CLIENT_ISOLATION)
/**
 * \brief Get the fs_ctx for given client_id.
 *
 * \return Returns ETSS_SUCCESS if there is already a fs_ctx for given fs_ctx,
 *         and ETSS_ERROR_DOES_NOT_EXIST otherwise.
 */
etss_err_t etss_get_fs_ctx(int32_t client_id, etss_flash_fs_ctx_t *fs_ctx)
{
    for (uint8_t i = 0; i < SECURE_FLASH_CLIENT_NUM; i++) {
        if (etss_fs_ctx_tbl[i].client_id == client_id) {
            fs_ctx = &(etss_fs_ctx_tbl[i].fs_ctx);
            return ETSS_SUCCESS;
        }
    }
    return ETSS_ERROR_DOES_NOT_EXIST;
}
#endif

/**
 * \brief Initialize the static filesystem configurations.
 *
 * \return Returns PSA_ERROR_PROGRAMMER_ERROR if there is a configuration error,
 *         and PSA_SUCCESS otherwise.
 */
etss_err_t init_fs_cfg(void)
{
#if defined(MULTI_CLIENT_ISOLATION)
    for (uint8_t i = 0; i < SECURE_FLASH_CLIENT_NUM; i++) {
        /* common cfg*/
        fs_cfg_etss[i].flash_dev = fs_cfg_etss_common.flash_dev;
        fs_cfg_etss[i].program_unit = fs_cfg_etss_common.program_unit;
        fs_cfg_etss[i].max_file_size = fs_cfg_etss_common.max_file_size;
        fs_cfg_etss[i].max_num_files = fs_cfg_etss_common.max_num_files;
        fs_cfg_etss[i].sector_size = SECURE_FLASH_SECTOR_SIZE;
        fs_cfg_etss[i].erase_val = SECURE_FLASH_ERASED_VALUE;
        /* specific cfg*/
        fs_cfg_etss[i].flash_area_addr = SECURE_FLASH_CLIENT_AREA_START_ADDR(i);
        fs_cfg_etss[i].block_size = fs_cfg_etss[i].sector_size *
                                    SECURE_FLASH_CLIENT_SECTORS_PER_BLOCK(i);
        fs_cfg_etss[i].num_blocks = SECURE_FLASH_CLIENT_AREA_SIZE(i) /
                                    fs_cfg_etss[i].block_size;
    }
#else
    /* Retrieve flash properties from the ETSS flash driver */
    fs_cfg_etss_common.sector_size = SECURE_FLASH_SECTOR_SIZE;
    fs_cfg_etss_common.erase_val = SECURE_FLASH_ERASED_VALUE;
    /* Retrieve FS parameters defined in secureflash_layout.h */
    fs_cfg_etss_common.flash_area_addr = SECURE_FLASH_START_ADDR;
    fs_cfg_etss_common.block_size = fs_cfg_etss_common.sector_size *
                                    SECURE_FLASH_SECTORS_PER_BLOCK;
    fs_cfg_etss_common.num_blocks = SECURE_FLASH_SIZE /
                                    fs_cfg_etss_common.block_size;
#endif
    return ETSS_SUCCESS;
}

etss_err_t etss_flash_fs_init_ctx_and_prepare(
                                    etss_flash_fs_ctx_t *fs_ctx,
                                    const struct etss_flash_fs_config_t *fs_cfg,
                                    const struct etss_flash_fs_ops_t *fs_ops)
{
    psa_status_t status;
    status = etss_flash_fs_init_ctx(fs_ctx, fs_cfg, fs_ops);
    if (status == PSA_SUCCESS) {
        /* Prepare the ETSS filesystem */
        status = etss_flash_fs_prepare(fs_ctx);

#ifdef ETSS_CREATE_FLASH_LAYOUT
        /* If ETSS_CREATE_FLASH_LAYOUT is set, it indicates that it is required
         * to create a ETSS flash layout. ETSS service will generate an empty
         * and valid ETSS flash layout to store assets. It will erase all data
         * located in the assigned ETSS memory area before generating the ETSS
         * layout.
         * This flag can be set if the ETSS memory area is located in persistent
         * memory without a previous valid ETSS flash layout in it. That is the
         * case when it is the first time in the device life that the ETSS
         * service is executed.
         */
        if (status != PSA_SUCCESS) {
            /* Remove all data in the ETSS memory area and create a valid ETSS
             * flash layout in that area.
             */
            status = etss_flash_fs_wipe_all(fs_ctx);
            if (status != PSA_SUCCESS) {
                return status;
            }
            /* Attempt to prepare again */
            status = etss_flash_fs_prepare(fs_ctx);
        }
#endif /* ETSS_CREATE_FLASH_LAYOUT */
        if (status == PSA_SUCCESS) {
            return ETSS_SUCCESS;
        }
    }
    return ETSS_ERR_STORAGE_FAILURE;
}


etss_err_t etss_init(void)
{
    int32_t err;
    err = secureflash_init(&secureflash);
    if (err != SECUREFLASH_ERROR_OK) {
        if (err == SECUREFLASH_ERROR_UNPROVISIONED) {
            return ETSS_ERR_SF_UNPROVISIONED;
        } else {
            return ETSS_ERR_STORAGE_FAILURE;
        }
    }
    if (secureflash.sf_ctx->flash_profile.security_feature.security_storage) {
        err = init_fs_cfg();
        if (err != ETSS_SUCCESS) {
            return err;
        }
        /* Initialize the ETSS filesystem context */
    #if defined(MULTI_CLIENT_ISOLATION)
        for (uint8_t i = 0; i < SECURE_FLASH_CLIENT_NUM; i++) {
            etss_fs_ctx_tbl[i].client_id = SECURE_FLASH_CLIENT_ID(i);
            err = etss_flash_fs_init_ctx_and_prepare(
                                                  &(etss_fs_ctx_tbl[i].fs_ctx),
                                                  &fs_cfg_etss[i],
                                                  &etss_secure_flash_fs_ops);
            if (err != ETSS_SUCCESS) {
                return ETSS_ERR_STORAGE_FAILURE;
            }
        }
    #else
        err = etss_flash_fs_init_ctx_and_prepare(&fs_ctx_etss,
                                                 &fs_cfg_etss_common,
                                                 &etss_secure_flash_fs_ops);
        if (err != ETSS_SUCCESS) {
            return ETSS_ERR_STORAGE_FAILURE;
        }
    #endif /* defined(MULTI_CLIENT_ISOLATION) */
    }
    return err;
}

etss_err_t etss_secure_flash_provisioning(int32_t client_id,
                                          uint8_t *prov_data,
                                          size_t data_length)
{
    int32_t status;
    status = secureflash_write_provision(&secureflash, prov_data);
    if (status) {
        return ETSS_ERR_SF_PROVISION;
    } else {
        return ETSS_SUCCESS;
    }
    /* FIXME:Verify provisioning data is needed */
    /* FIXME:Has been provisioned already */
}

etss_err_t etss_set(int32_t client_id,
                    psa_storage_uid_t uid,
                    size_t data_length,
                    psa_storage_create_flags_t create_flags)
{
    psa_status_t status;
    size_t write_size;
    size_t offset;
    uint32_t flags;
    if (secureflash.sf_ctx->flash_profile.security_feature.security_storage) {
        /* Check that the UID is valid */
        if (uid == ETSS_INVALID_UID) {
            return ETSS_ERR_INVALID_ARGUMENT;
        }
        /* Check that the create_flags does not contain any unsupported flags */
        if (create_flags & ~(PSA_STORAGE_FLAG_WRITE_ONCE |
                           PSA_STORAGE_FLAG_NO_CONFIDENTIALITY |
                           PSA_STORAGE_FLAG_NO_REPLAY_PROTECTION)) {
            return ETSS_ERR_NOT_SUPPORTED;
        }
        /* Set file id */
        tfm_memset(g_fid, 0x00, ETSS_FILE_ID_SIZE);
        etss_get_fid(client_id, uid, g_fid);
        etss_client_id_pass_through(client_id);
#if defined(MULTI_CLIENT_ISOLATION)
        if (etss_get_fs_ctx(client_id, fs_ctx_etss_ptr)) {
            return ETSS_ERR_NOT_SUPPORTED;
        }
#endif
        status = etss_flash_fs_file_get_info(fs_ctx_etss_ptr, g_fid,
                                             &g_file_info);
        if (status == PSA_SUCCESS) {
            /* If the object exists and has the write once flag set, then it
             * cannot be modified.
             */
            if (g_file_info.flags & PSA_STORAGE_FLAG_WRITE_ONCE) {
                return ETSS_ERR_NOT_PERMITTED;
            }
        } else if (status != PSA_ERROR_DOES_NOT_EXIST) {
            /* If the file does not exist, then do nothing.
             * If other error occurred, return it
             */
            return (etss_err_t)status;
        }
        offset = 0;
        flags = (uint32_t)create_flags |
                ETSS_FLASH_FS_FLAG_CREATE | ETSS_FLASH_FS_FLAG_TRUNCATE;
        /* Iteratively read data from the caller and write it to the filesystem,
         * in chunks no larger than the size of the asset_data buffer.
         */
        do {
            /* Write as much of the data as will fit in the asset_data buffer */
            write_size = ETSS_UTILS_MIN(data_length, sizeof(asset_data));
            /* Read asset data from the caller */
            (void)etss_req_mngr_read(asset_data, write_size);
            /* Write to the file in the file system */
            status = etss_flash_fs_file_write(fs_ctx_etss_ptr, g_fid, flags,
                                              data_length, write_size, offset,
                                              asset_data);
            if (status != PSA_SUCCESS) {
                return (etss_err_t)status;
            }
            /* Do not create or truncate after the first iteration */
            flags &= ~(ETSS_FLASH_FS_FLAG_CREATE | ETSS_FLASH_FS_FLAG_TRUNCATE);
            offset += write_size;
            data_length -= write_size;
        } while (data_length > 0);
        return ETSS_SUCCESS;
    } else {
        return ETSS_ERR_NOT_SUPPORTED;
    }
}

etss_err_t etss_get(int32_t client_id,
                    psa_storage_uid_t uid,
                    size_t data_offset,
                    size_t data_size,
                    size_t *p_data_length)
{
    psa_status_t status;
    size_t read_size;
    if (secureflash.sf_ctx->flash_profile.security_feature.security_storage) {
        /* Check that the UID is valid */
        if (uid == ETSS_INVALID_UID) {
            return ETSS_ERR_INVALID_ARGUMENT;
        }
        /* Set file id */
        tfm_memset(g_fid, 0x00, ETSS_FILE_ID_SIZE);
        etss_get_fid(client_id, uid, g_fid);
        /* Pass client id to underlying etss_secureflash */
        etss_client_id_pass_through(client_id);
    #if defined(MULTI_CLIENT_ISOLATION)
        if (etss_get_fs_ctx(client_id, fs_ctx_etss_ptr)) {
            return ETSS_ERR_NOT_SUPPORTED;
        }
    #endif
        /* Read file info */
        status = etss_flash_fs_file_get_info(fs_ctx_etss_ptr, g_fid,
                                             &g_file_info);
        if (status != PSA_SUCCESS) {
            return (etss_err_t)status;
        }
        /* Boundary check the incoming request */
        if (data_offset > g_file_info.size_current) {
            return ETSS_ERR_INVALID_ARGUMENT;
        }
        /* Copy the object data only from within the file boundary */
        data_size = ETSS_UTILS_MIN(data_size,
                                   g_file_info.size_current - data_offset);
        /* Update the size of the output data */
        *p_data_length = data_size;
        /* Iteratively read data from the filesystem and write it to the caller,
         * in chunks no larger than the size of the asset_data buffer.
         */
        do {
            /* Read as much of the data as will fit in the asset_data buffer */
            read_size = ETSS_UTILS_MIN(data_size, sizeof(asset_data));
            /* Read file data from the filesystem */
            status = etss_flash_fs_file_read(fs_ctx_etss_ptr, g_fid, read_size,
                                             data_offset, asset_data);
            if (status != PSA_SUCCESS) {
                *p_data_length = 0;
                return (etss_err_t)status;
            }
            /* Write asset data to the caller */
            etss_req_mngr_write(asset_data, read_size);
            data_offset += read_size;
            data_size -= read_size;
        } while (data_size > 0);
        return ETSS_SUCCESS;
    } else {
        return ETSS_ERR_NOT_SUPPORTED;
    }
}

etss_err_t etss_get_info(int32_t client_id, psa_storage_uid_t uid,
                         struct psa_storage_info_t *p_info)
{
    psa_status_t status;
    if (secureflash.sf_ctx->flash_profile.security_feature.security_storage) {
        /* Check that the UID is valid */
        if (uid == ETSS_INVALID_UID) {
            return ETSS_ERR_INVALID_ARGUMENT;
        }
        /* Set file id */
        tfm_memset(g_fid, 0x00, ETSS_FILE_ID_SIZE);
        etss_get_fid(client_id, uid, g_fid);
        etss_client_id_pass_through(client_id);
#if defined(MULTI_CLIENT_ISOLATION)
        if (etss_get_fs_ctx(client_id, fs_ctx_etss_ptr)) {
            return ETSS_ERR_NOT_SUPPORTED;
        }
#endif
        /* Read file info */
        status = etss_flash_fs_file_get_info(fs_ctx_etss_ptr, g_fid,
                                             &g_file_info);
        if (status != PSA_SUCCESS) {
            return (etss_err_t)status;
        }
        /* Copy file info to the PSA info struct */
        p_info->capacity = g_file_info.size_current;
        p_info->size = g_file_info.size_current;
        p_info->flags = g_file_info.flags;
        return ETSS_SUCCESS;
    } else {
        return ETSS_ERR_NOT_SUPPORTED;
    }
}

etss_err_t etss_remove(int32_t client_id, psa_storage_uid_t uid)
{
    psa_status_t status;
    if (secureflash.sf_ctx->flash_profile.security_feature.security_storage) {
        /* Check that the UID is valid */
        if (uid == ETSS_INVALID_UID) {
            return ETSS_ERR_INVALID_ARGUMENT;
        }
        /* Set file id */
        tfm_memset(g_fid, 0x00, ETSS_FILE_ID_SIZE);
        etss_get_fid(client_id, uid, g_fid);
        etss_client_id_pass_through(client_id);
#if defined(MULTI_CLIENT_ISOLATION)
        if (etss_get_fs_ctx(client_id, fs_ctx_etss_ptr)) {
            return ETSS_ERR_NOT_SUPPORTED;
        }
#endif
        /* Read file info */
        status = etss_flash_fs_file_get_info(fs_ctx_etss_ptr, g_fid,
                                             &g_file_info);
        if (status != PSA_SUCCESS) {
            return (etss_err_t)status;
        }
        /* If the object exists and has the write once flag set, then it
         * cannot be deleted.
         */
        if (g_file_info.flags & PSA_STORAGE_FLAG_WRITE_ONCE) {
            return ETSS_ERR_NOT_PERMITTED;
        }
        /* Delete old file from the persistent area */
        status = etss_flash_fs_file_delete(fs_ctx_etss_ptr, g_fid);
        return (etss_err_t)status;
    } else {
        return ETSS_ERR_NOT_SUPPORTED;
    }
}

etss_err_t etss_get_puf(int32_t client_id, size_t buf_size, size_t *puf_len)
{
    uint8_t puf[SECURE_FLASH_MAX_PUF_SIZE];
    int32_t status;
    uint8_t actual_size;
    if (secureflash.sf_ctx->flash_profile.security_feature.PUF) {
        status = secureflash_get_puf(&secureflash, puf, sizeof(puf),
                                     &actual_size, NULL, 0);
        if (SECUREFLASH_ERROR_OK != status) {
            return ETSS_ERR_STORAGE_FAILURE;
        }
        buf_size = ETSS_UTILS_MIN(buf_size, actual_size);
        etss_req_mngr_write(puf, buf_size);
        *puf_len = buf_size;
        return ETSS_SUCCESS;
    } else {
        return ETSS_ERR_NOT_SUPPORTED;
    }
}

etss_err_t etss_generate_random_number(int32_t client_id, size_t buf_size,
                                       size_t *random_len)
{
    uint8_t random[SECURE_FLASH_MAX_TRNG_SIZE];
    int32_t status;
    uint8_t actual_size;
    *random_len = 0;
    if (secureflash.sf_ctx->flash_profile.security_feature.RNG) {
        while (buf_size > 0) {
            status = secureflash_get_trng(&secureflash, random, buf_size,
                                          &actual_size);
            if (SECUREFLASH_ERROR_OK != status) {
                return ETSS_ERR_STORAGE_FAILURE;
            }
            actual_size = ETSS_UTILS_MIN(buf_size, actual_size);
            etss_req_mngr_write(random, actual_size);
            buf_size -= actual_size;
            *random_len += actual_size;
        }
        return ETSS_SUCCESS;
    } else {
        return ETSS_ERR_NOT_SUPPORTED;
    }
}

etss_err_t etss_mc_increment(int32_t client_id, uint8_t mc_id)
{
    if (secureflash.sf_ctx->flash_profile.security_feature.RPMC) {
        if (0 != secureflash_increase_mc(&secureflash, mc_id, client_id)) {
            return ETSS_ERR_STORAGE_FAILURE;
        }
        return ETSS_SUCCESS;
    } else {
        return ETSS_ERR_NOT_SUPPORTED;
    }
}

etss_err_t etss_mc_get(int32_t client_id, uint8_t mc_id, size_t size)
{
    uint8_t mc[SECURE_FLASH_MAX_MC_SIZE];
    uint8_t actual_size;
    if (secureflash.sf_ctx->flash_profile.security_feature.RPMC) {
        if (0 != secureflash_get_mc(&secureflash, mc_id, mc, size, &actual_size,
                                    client_id)) {
            return ETSS_ERR_STORAGE_FAILURE;
        }
        size = ETSS_UTILS_MIN(size, actual_size);
        etss_req_mngr_write(mc, size);
        return ETSS_SUCCESS;
    } else {
        return ETSS_ERR_NOT_SUPPORTED;
    }
}
