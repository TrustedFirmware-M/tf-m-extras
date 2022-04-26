/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <string.h>
#include "secureflash.h"
#include "psa_manifest/pid.h"
#include "tfm_memory_utils.h"

static app_info_t app_info;

static app_data_t *query_app_info(secureflash_t *secureflash, size_t addr,
                                  int32_t app_id)
{
    uint32_t n;
    uint32_t zone_id;

    zone_id =
       addr/(secureflash->sf_ctx->flash_profile.architecture.secure_zone_size);
    if (app_id == SP_ETSS) {
        for (n = 0; n < secureflash->app_info->num; n++) {
            if (secureflash->app_info->app_data[n].zone_id == zone_id) {
                return &(secureflash->app_info->app_data[n]);
            }
        }
    } else {
        for (n = 0; n < secureflash->app_info->num; n++) {
            if ((secureflash->app_info->app_data[n].app_id == app_id)
                && (secureflash->app_info->app_data[n].zone_id == zone_id)) {
                return &(secureflash->app_info->app_data[n]);
            }
        }
    }
    return NULL;
}

int32_t secureflash_init(secureflash_t *secureflash)
{
    int32_t status = SECUREFLASH_ERROR_OK;

    if (!secureflash->_is_initialized) {
        secureflash->_init_ref_count = 0;
    }
    secureflash->_init_ref_count++;
    if (secureflash->_init_ref_count != 1) {
        goto init_exit_point;
    }
    if (secureflash->vendor_op_register == NULL) {
        status = SECUREFLASH_ERROR_INITIAL;
        goto init_exit_point;
    }
    if (0 != sf_common_create_and_init_context(secureflash->vendor_op_register,
                                               &(secureflash->sf_ctx))) {
        status = SECUREFLASH_ERROR_INITIAL;
        goto init_exit_point;
    }
    status = sf_common_init(secureflash->sf_ctx);
    if (status) {
        if (SECUREFLASH_ERROR_UNPROVISIONED == status) {
            return SECUREFLASH_ERROR_UNPROVISIONED;
        }
        status = SECUREFLASH_ERROR_INITIAL;
        goto init_exit_point;
    }
    tfm_memset(&app_info, 0x00, sizeof(app_info_t));
    secureflash->app_info = &app_info;
    if (0 !=
          sf_common_get_app_info(secureflash->sf_ctx, secureflash->app_info)) {
        status = SECUREFLASH_ERROR_INITIAL;
        goto init_exit_point;
    }
    secureflash->_is_initialized = true;
init_exit_point:
    return status;
}

int32_t secureflash_deinit(secureflash_t *secureflash)
{
    int32_t status = SECUREFLASH_ERROR_OK;

    sf_common_deinit(secureflash->sf_ctx);
    if (secureflash->app_info != NULL) {
        secureflash->app_info = NULL;
    }
    secureflash->_init_ref_count--;
    if (secureflash->_init_ref_count) {
        goto deinit_exit_point;
    }
    if (!secureflash->_is_initialized) {
        secureflash->_init_ref_count = 0;
        goto deinit_exit_point;
    }
    secureflash->_is_initialized = false;
deinit_exit_point:
    return status;
}

int32_t secureflash_secure_read(secureflash_t *secureflash, void *buffer,
                                size_t addr, size_t size, int32_t app_id)
{
    int32_t status = SECUREFLASH_ERROR_OK;
    app_data_t *app_data;
    uint32_t session_id = 0;

    if (!secureflash->_is_initialized) {
        return SECUREFLASH_ERROR_DEVICE;
    }
    app_data = query_app_info(secureflash, addr, app_id);
    if (NULL == app_data) {
        status = SECUREFLASH_ERROR_ILLEGAL_ACCESS;
        goto secure_read_exit_point;
    }
    if (0 != sf_common_create_session(secureflash->sf_ctx, app_data->key_id,
                                      &session_id)) {
        status = SECUREFLASH_ERROR_SECURE_READ;
        goto secure_read_exit_point;
    }
    if (0 != sf_common_secure_read(secureflash->sf_ctx, (uint8_t *)buffer, addr,
                                   size, session_id)) {
        status = SECUREFLASH_ERROR_SECURE_READ;
        goto secure_read_exit_point;
    }
    if (0 != sf_common_close_session(secureflash->sf_ctx, session_id)) {
        status = SECUREFLASH_ERROR_SECURE_READ;
        goto secure_read_exit_point;
    }
secure_read_exit_point:
    return status;
}

int32_t secureflash_secure_program(secureflash_t *secureflash,
                                   const void *buffer,
                                   size_t addr, size_t size, int32_t app_id)
{
    int32_t status = SECUREFLASH_ERROR_OK;
    app_data_t *app_data;
    uint32_t session_id = 0;

    if (!secureflash->_is_initialized) {
        return SECUREFLASH_ERROR_DEVICE;
    }
    app_data = query_app_info(secureflash, addr, app_id);
    if (NULL == app_data) {
        status = SECUREFLASH_ERROR_ILLEGAL_ACCESS;
        goto secure_program_exit_point;
    }
    if (0 != sf_common_create_session(secureflash->sf_ctx, app_data->key_id,
                                      &session_id)) {
        status = SECUREFLASH_ERROR_SECURE_PROGRAM;
        goto secure_program_exit_point;
    }
    if (0 != sf_common_secure_program(secureflash->sf_ctx, (uint8_t *)buffer,
                                      addr, size, session_id)) {
        status = SECUREFLASH_ERROR_SECURE_PROGRAM;
        goto secure_program_exit_point;
    }
    if (0 != sf_common_close_session(secureflash->sf_ctx, session_id)) {
        status = SECUREFLASH_ERROR_SECURE_PROGRAM;
        goto secure_program_exit_point;
    }
secure_program_exit_point:
    return status;
}


int32_t secureflash_secure_erase(secureflash_t *secureflash, size_t addr,
                                 size_t size, int32_t app_id)
{
    int32_t status = SECUREFLASH_ERROR_OK;
    app_data_t *app_data;
    uint32_t session_id;

    if (!secureflash->_is_initialized) {
        return SECUREFLASH_ERROR_DEVICE;
    }
    app_data = query_app_info(secureflash, addr, app_id);
    if (NULL == app_data) {
        status = SECUREFLASH_ERROR_ILLEGAL_ACCESS;
        goto secure_erase_exit_point;
    }
    if (0 != sf_common_create_session(secureflash->sf_ctx, app_data->key_id,
                                      &session_id)) {
        status = SECUREFLASH_ERROR_SECURE_ERASE;
        goto secure_erase_exit_point;
    }
    if (0 !=
         sf_common_secure_erase(secureflash->sf_ctx, addr, size, session_id)) {
        status = SECUREFLASH_ERROR_SECURE_ERASE;
        goto secure_erase_exit_point;
    }
    if (0 != sf_common_close_session(secureflash->sf_ctx, session_id)) {
        status = SECUREFLASH_ERROR_SECURE_ERASE;
        goto secure_erase_exit_point;
    }
secure_erase_exit_point:
    return status;
}

int32_t secureflash_get_puf(secureflash_t *secureflash, uint8_t *puf,
                            uint8_t size, uint8_t *actual_size,
                            uint8_t *input_data, uint8_t input_data_size)
{
    if (!secureflash->_is_initialized) {
        return SECUREFLASH_ERROR_DEVICE;
    }
    if (0 != sf_common_get_puf(secureflash->sf_ctx, puf, size, actual_size,
                               input_data, input_data_size)) {
        return SECUREFLASH_ERROR_GET_PUF;
    }
    return SECUREFLASH_ERROR_OK;
}

int32_t secureflash_get_trng(secureflash_t *secureflash, uint8_t *random,
                             uint8_t size, uint8_t *actual_size)
{
    if (!secureflash->_is_initialized) {
        return SECUREFLASH_ERROR_DEVICE;
    }
    if (0 !=
          sf_common_get_trng(secureflash->sf_ctx, random, size, actual_size)) {
        return SECUREFLASH_ERROR_GET_TRNG;
    }
    return SECUREFLASH_ERROR_OK;
}

int32_t secureflash_get_uid(secureflash_t *secureflash, uint8_t *uid,
                            uint8_t size, uint8_t *actual_size)
{
    if (!secureflash->_is_initialized) {
        return SECUREFLASH_ERROR_DEVICE;
    }
    if (0 != sf_common_get_uid(secureflash->sf_ctx, uid, size, actual_size)) {
        return SECUREFLASH_ERROR_GET_PUF;
    }
    return SECUREFLASH_ERROR_OK;
}

static bool mc_access_grant(secureflash_t *secureflash, int32_t client_id,
                            uint8_t mc_addr, uint32_t *key_id)
{
    uint8_t n;
    app_data_t *app_data_ptr = secureflash->app_info->app_data;
    for (n = 0; n < APP_INFO_MAX_NUM; n++) {
        if ((app_data_ptr->app_id == client_id)
            && (app_data_ptr->mc_id == mc_addr)) {
            *key_id = app_data_ptr->key_id;
            return true;
        }
        app_data_ptr++;
    }
    return false;
}

#define DEFAULT_MC_MAX_SIZE 8

int32_t secureflash_increase_mc(secureflash_t *secureflash, uint8_t mc_addr,
                                int32_t app_id)
{
    int32_t status = SECUREFLASH_ERROR_OK;
    uint8_t mc[DEFAULT_MC_MAX_SIZE], actual_size;
    uint32_t rpmc_root_key_id;
    if (!secureflash->_is_initialized) {
        return SECUREFLASH_ERROR_DEVICE;
    }
    if (!mc_access_grant(secureflash, app_id, mc_addr, &rpmc_root_key_id)) {
        return SECUREFLASH_ERROR_ILLEGAL_ACCESS;
    }
    if (0 != sf_common_rpmc_update_hmac_key(secureflash->sf_ctx, mc_addr,
                                            rpmc_root_key_id)) {
        return SECUREFLASH_ERROR_INCREASE_MC;
    }

    if (0 != sf_common_get_mc(secureflash->sf_ctx, mc_addr, mc,
                              DEFAULT_MC_MAX_SIZE, &actual_size)) {
        status = SECUREFLASH_ERROR_GET_MC;
        goto increase_mc_exit_point;
    }
    if (0 != sf_common_increase_mc(secureflash->sf_ctx, mc_addr, mc)) {
        status = SECUREFLASH_ERROR_INCREASE_MC;
        goto increase_mc_exit_point;
    }
increase_mc_exit_point:
    return status;
}

int32_t secureflash_get_mc(secureflash_t *secureflash, uint8_t mc_addr,
                           uint8_t *mc, uint8_t size, uint8_t *actual_size,
                           int32_t app_id)
{
    uint32_t rpmc_root_key_id;
    if (!secureflash->_is_initialized) {
        return SECUREFLASH_ERROR_DEVICE;
    }
    if (!mc_access_grant(secureflash, app_id, mc_addr, &rpmc_root_key_id)) {
        return SECUREFLASH_ERROR_ILLEGAL_ACCESS;
    }
    if (0 != sf_common_rpmc_update_hmac_key(secureflash->sf_ctx, mc_addr,
                                            rpmc_root_key_id)) {
        return SECUREFLASH_ERROR_GET_MC;
    }
    if (0 != sf_common_get_mc(secureflash->sf_ctx, mc_addr, mc, size,
                              actual_size)) {
        return SECUREFLASH_ERROR_GET_MC;
    }
    return SECUREFLASH_ERROR_OK;
}

int32_t secureflash_write_provision(secureflash_t *secureflash,
                                    void *provision_data)
{
    if (0 != sf_common_write_provision(secureflash->sf_ctx, provision_data)) {
        return SECUREFLASH_ERROR_WRITE_PROVISION;
    }
    return SECUREFLASH_ERROR_OK;
}

int32_t secureflash_read_provision(secureflash_t *secureflash,
                                   void *provision_data)
{
    if (!secureflash->_is_initialized) {
        return SECUREFLASH_ERROR_DEVICE;
    }
    if (0 != sf_common_read_provision(secureflash->sf_ctx, provision_data)) {
        return SECUREFLASH_ERROR_READ_PROVISION;
    }
    return SECUREFLASH_ERROR_OK;
}

int32_t secureflash_lock_provision(secureflash_t *secureflash,
                                   void *provision_data)
{
    if (!secureflash->_is_initialized) {
        return SECUREFLASH_ERROR_DEVICE;
    }
    if (0 != sf_common_lock_provision(secureflash->sf_ctx, provision_data)) {
        return SECUREFLASH_ERROR_LOCK_PROVISION;
    }
    return SECUREFLASH_ERROR_OK;
}
