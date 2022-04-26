/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdint.h>
#include "etss_req_mngr.h"
#include "psa/storage_common.h"
#include "psa/service.h"
#include "psa_manifest/etss.h"
#include "external_trusted_secure_storage.h"
#include "etss/etss_defs.h"
#include "tfm_hal_platform.h"

typedef etss_err_t (*etss_func_t)(void);
static psa_msg_t msg;


static etss_err_t etss_set_ipc(void)
{
    psa_storage_uid_t uid;
    size_t data_length;
    psa_storage_create_flags_t create_flags;
    size_t num;

    if (msg.in_size[0] != sizeof(uid) ||
        msg.in_size[2] != sizeof(create_flags)) {
        /* The size of one of the arguments is incorrect */
        return ETSS_ERR_PROGRAMMER_ERROR;
    }
    data_length = msg.in_size[1];
    num = psa_read(msg.handle, 0, &uid, sizeof(uid));
    if (num != sizeof(uid)) {
        return ETSS_ERR_PROGRAMMER_ERROR;
    }
    num = psa_read(msg.handle, 2, &create_flags, sizeof(create_flags));
    if (num != sizeof(create_flags)) {
        return ETSS_ERR_PROGRAMMER_ERROR;
    }
    return etss_set(msg.client_id, uid, data_length, create_flags);
}

static etss_err_t etss_get_ipc(void)
{
    psa_storage_uid_t uid;
    size_t data_offset;
    size_t data_size;
    size_t data_length;
    size_t num;

    if (msg.in_size[0] != sizeof(uid) ||
        msg.in_size[1] != sizeof(data_offset)) {
        /* The size of one of the arguments is incorrect */
        return ETSS_ERR_PROGRAMMER_ERROR;
    }
    data_size = msg.out_size[0];
    num = psa_read(msg.handle, 0, &uid, sizeof(uid));
    if (num != sizeof(uid)) {
        return ETSS_ERR_PROGRAMMER_ERROR;
    }
    num = psa_read(msg.handle, 1, &data_offset, sizeof(data_offset));
    if (num != sizeof(data_offset)) {
        return ETSS_ERR_PROGRAMMER_ERROR;
    }
    return etss_get(msg.client_id, uid, data_offset, data_size,
                    &data_length);
}

static etss_err_t etss_get_info_ipc(void)
{
    etss_err_t err;
    psa_storage_uid_t uid;
    struct psa_storage_info_t info;
    size_t num;

    if (msg.in_size[0] != sizeof(uid) ||
        msg.out_size[0] != sizeof(info)) {
        /* The size of one of the arguments is incorrect */
        return ETSS_ERR_PROGRAMMER_ERROR;
    }
    num = psa_read(msg.handle, 0, &uid, sizeof(uid));
    if (num != sizeof(uid)) {
        return ETSS_ERR_PROGRAMMER_ERROR;
    }
    err = etss_get_info(msg.client_id, uid, &info);
    if (err == ETSS_SUCCESS) {
        psa_write(msg.handle, 0, &info, sizeof(info));
    }
    return err;
}

static etss_err_t etss_remove_ipc(void)
{
    psa_storage_uid_t uid;
    size_t num;

    if (msg.in_size[0] != sizeof(uid)) {
        /* The input argument size is incorrect */
        return ETSS_ERR_PROGRAMMER_ERROR;
    }
    num = psa_read(msg.handle, 0, &uid, sizeof(uid));
    if (num != sizeof(uid)) {
        return ETSS_ERR_PROGRAMMER_ERROR;
    }
    return etss_remove(msg.client_id, uid);
}

static etss_err_t etss_get_puf_ipc(void)
{
    size_t data_size;
    size_t data_length;

    data_size = msg.out_size[0];
    return etss_get_puf(msg.client_id, data_size, &data_length);
}

static etss_err_t etss_generate_random_number_ipc(void)
{
    size_t data_size;
    size_t data_length;

    data_size = msg.out_size[0];
    return etss_generate_random_number(msg.client_id, data_size, &data_length);
}

static etss_err_t etss_mc_increment_ipc(void)
{
    size_t num;
    uint8_t mc_id;

    num = psa_read(msg.handle, 0, &mc_id, sizeof(mc_id));
    if (num != sizeof(mc_id)) {
        return ETSS_ERR_PROGRAMMER_ERROR;
    }
    return etss_mc_increment(msg.client_id, mc_id);
}

static etss_err_t etss_mc_get_ipc(void)
{
    size_t num;
    uint8_t mc_id;
    size_t mc_size;

    num = psa_read(msg.handle, 0, &mc_id, sizeof(mc_id));
    if (num != sizeof(mc_id)) {
        return ETSS_ERR_PROGRAMMER_ERROR;
    }
    mc_size = msg.out_size[0];
    return etss_mc_get(msg.client_id, mc_id, mc_size);
}

static int32_t etss_secure_flash_provisioning_ipc(const psa_msg_t *msg)
{
    size_t data_length;
    size_t num;
    uint8_t prov_data[PROV_BLOB_LEN_MAX] = {0};
    data_length = msg->in_size[0];
    if (data_length > PROV_BLOB_LEN_MAX) {
        return ETSS_ERR_GENERIC_ERROR;
    }
    num = psa_read(msg->handle, 0, prov_data, data_length);
    if (num != data_length) {
        return ETSS_ERR_PROGRAMMER_ERROR;
    }
    return etss_secure_flash_provisioning(msg->client_id, prov_data,
                                          data_length);
}

static void etss_signal_handle(psa_signal_t signal, etss_func_t pfn)
{
    psa_status_t status;

    status = psa_get(signal, &msg);
    if (status != PSA_SUCCESS) {
        return;
    }
    switch (msg.type) {
    case PSA_IPC_CONNECT:
        psa_reply(msg.handle, PSA_SUCCESS);
        break;
    case PSA_IPC_CALL:
        status = (psa_status_t)pfn();
        psa_reply(msg.handle, status);
        break;
    case PSA_IPC_DISCONNECT:
        psa_reply(msg.handle, PSA_SUCCESS);
        break;
    default:
        psa_panic();
    }
}


etss_err_t etss_req_mngr_init(void)
{
    etss_err_t err;
    psa_status_t status;
    psa_signal_t signals = 0;

    err = etss_init();
    if (err != ETSS_SUCCESS) {
        if (err == ETSS_ERR_SF_UNPROVISIONED) {
            while (1) {
                (void)psa_wait(ETSS_SECURE_FLASH_PROVISIONING_SIGNAL, PSA_BLOCK);
                (void)psa_get(ETSS_SECURE_FLASH_PROVISIONING_SIGNAL, &msg);
                switch (msg.type) {
                case PSA_IPC_CONNECT:
                case PSA_IPC_DISCONNECT:
                    psa_reply(msg.handle, PSA_SUCCESS);
                    break;
                case PSA_IPC_CALL:
                    status =
                        (psa_status_t)etss_secure_flash_provisioning_ipc(&msg);
                    psa_reply(msg.handle, status);
                    break;
                }
            }
        }
        tfm_hal_system_reset();/* Reset */
    }
    while (1) {
        signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);
        if (signals & ETSS_SET_SIGNAL) {
            etss_signal_handle(ETSS_SET_SIGNAL, etss_set_ipc);
        } else if (signals & ETSS_GET_SIGNAL) {
            etss_signal_handle(ETSS_GET_SIGNAL, etss_get_ipc);
        } else if (signals & ETSS_GET_INFO_SIGNAL) {
            etss_signal_handle(ETSS_GET_INFO_SIGNAL, etss_get_info_ipc);
        } else if (signals & ETSS_REMOVE_SIGNAL) {
            etss_signal_handle(ETSS_REMOVE_SIGNAL, etss_remove_ipc);
        } else if (signals & ETSS_GET_PUF_SIGNAL) {
            etss_signal_handle(ETSS_GET_PUF_SIGNAL, etss_get_puf_ipc);
        } else if (signals & ETSS_GENERATE_RANDOM_NUMBER_SIGNAL) {
            etss_signal_handle(ETSS_GENERATE_RANDOM_NUMBER_SIGNAL,
                               etss_generate_random_number_ipc);
        } else if (signals & ETSS_MC_INCREMENT_SIGNAL) {
            etss_signal_handle(ETSS_MC_INCREMENT_SIGNAL, etss_mc_increment_ipc);
        } else if (signals & ETSS_MC_GET_SIGNAL) {
            etss_signal_handle(ETSS_MC_GET_SIGNAL, etss_mc_get_ipc);
        }
        else {
            psa_panic();
        }
    }
}

size_t etss_req_mngr_read(uint8_t *buf, size_t num_bytes)
{
    return psa_read(msg.handle, 1, buf, num_bytes);
}

void etss_req_mngr_write(const uint8_t *buf, size_t num_bytes)
{
    psa_write(msg.handle, 0, buf, num_bytes);
}
