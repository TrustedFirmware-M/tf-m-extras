/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "etss/etss_api.h"
#include "psa/client.h"
#include "psa_manifest/sid.h"


etss_err_t tfm_etss_secure_flash_provisioning(size_t data_length,
                                              const void *p_data)
{
    psa_status_t status;
    psa_handle_t handle;

    psa_invec in_vec[] = {
        { .base = p_data, .len = data_length }
    };
    handle = psa_connect(ETSS_SECURE_FLASH_PROVISIONING_SID,
                         ETSS_SECURE_FLASH_PROVISIONING_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return ETSS_ERR_GENERIC_ERROR;
    }
    status = psa_call(handle, PSA_IPC_CALL, in_vec, IOVEC_LEN(in_vec), NULL, 0);
    psa_close(handle);
    return (etss_err_t)status;
}

etss_err_t tfm_etss_set(psa_storage_uid_t uid,
                        size_t data_length,
                        const void *p_data,
                        psa_storage_create_flags_t create_flags)
{
    psa_status_t status;
    psa_handle_t handle;

    psa_invec in_vec[] = {
        { .base = &uid, .len = sizeof(uid) },
        { .base = p_data, .len = data_length },
        { .base = &create_flags, .len = sizeof(create_flags) }
    };
    handle = psa_connect(ETSS_SET_SID, ETSS_SET_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return ETSS_ERR_GENERIC_ERROR;
    }
    status = psa_call(handle, PSA_IPC_CALL, in_vec, IOVEC_LEN(in_vec), NULL, 0);
    psa_close(handle);
    /* A parameter with a buffer pointer where its data length is longer than
     * maximum permitted, it is treated as a secure violation.
     * TF-M framework rejects the request with TFM_ERROR_INVALID_PARAMETER.
     * The ETSS secure implementation returns ETSS_ERR_INVALID_ARGUMENT in
     * that case.
     */
    return (etss_err_t)status;
}

etss_err_t tfm_etss_get(psa_storage_uid_t uid,
                        size_t data_offset,
                        size_t data_size,
                        void *p_data,
                        size_t *p_data_length)
{
    psa_status_t status;
    psa_handle_t handle;

    psa_invec in_vec[] = {
        { .base = &uid, .len = sizeof(uid) },
        { .base = &data_offset, .len = sizeof(data_offset) }
    };
    psa_outvec out_vec[] = {
        { .base = p_data, .len = data_size }
    };
    if (p_data_length == NULL) {
        return ETSS_ERR_INVALID_ARGUMENT;
    }
    handle = psa_connect(ETSS_GET_SID, ETSS_GET_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return ETSS_ERR_GENERIC_ERROR;
    }
    status = psa_call(handle, PSA_IPC_CALL, in_vec, IOVEC_LEN(in_vec), out_vec,
                      IOVEC_LEN(out_vec));
    psa_close(handle);
    /* A parameter with a buffer pointer where its data length is longer than
     * maximum permitted or a parameter with a null pointer, it is treated as a
     * secure violation.
     * TF-M framework rejects the request with TFM_ERROR_INVALID_PARAMETER.
     * The ETSS secure implementation returns ETSS_ERR_INVALID_ARGUMENT in
     * that case.
     */
    *p_data_length = out_vec[0].len;
    return (etss_err_t)status;
}

etss_err_t tfm_etss_get_info(psa_storage_uid_t uid,
                             struct psa_storage_info_t *p_info)
{
    psa_status_t status;
    psa_handle_t handle;

    psa_invec in_vec[] = {
        { .base = &uid, .len = sizeof(uid) }
    };
    psa_outvec out_vec[] = {
        { .base = p_info, .len = sizeof(*p_info) }
    };
    handle = psa_connect(ETSS_GET_INFO_SID, ETSS_GET_INFO_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return ETSS_ERR_GENERIC_ERROR;
    }
    status = psa_call(handle, PSA_IPC_CALL, in_vec, IOVEC_LEN(in_vec), out_vec,
                      IOVEC_LEN(out_vec));
    psa_close(handle);
    /* A parameter with a null pointer is treated as a secure violation.
     * TF-M framework rejects the request with TFM_ERROR_INVALID_PARAMETER.
     * The ETSS secure implementation returns ETSS_ERR_INVALID_ARGUMENT in
     * that case.
     */
    return (etss_err_t)status;
}

etss_err_t tfm_etss_remove(psa_storage_uid_t uid)
{
    psa_status_t status;
    psa_handle_t handle;

    psa_invec in_vec[] = {
        { .base = &uid, .len = sizeof(uid) }
    };
    handle = psa_connect(ETSS_REMOVE_SID, ETSS_REMOVE_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return ETSS_ERR_GENERIC_ERROR;
    }
    status = psa_call(handle, PSA_IPC_CALL, in_vec, IOVEC_LEN(in_vec), NULL, 0);
    psa_close(handle);
    return (etss_err_t)status;
}

etss_err_t tfm_etss_get_puf(uint8_t *buf, uint32_t buf_size, uint32_t *puf_len)
{
    psa_status_t status;
    psa_handle_t handle;

    psa_outvec out_vec[] = {
      { .base = buf, .len = buf_size }
    };
    if (puf_len == NULL) {
        return ETSS_ERR_INVALID_ARGUMENT;
    }
    handle = psa_connect(ETSS_GET_PUF_SID, ETSS_GET_PUF_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return ETSS_ERR_GENERIC_ERROR;
    }
    status = psa_call(handle, PSA_IPC_CALL, NULL, 0, out_vec,
                      IOVEC_LEN(out_vec));
    psa_close(handle);
    *puf_len = out_vec[0].len;	
    return (etss_err_t)status;
}

etss_err_t tfm_etss_generate_random_number(uint8_t *buf, uint32_t buf_size)
{
    psa_status_t status;
    psa_handle_t handle;

    psa_outvec out_vec[] = {
        { .base = buf, .len = buf_size }
    };
    handle = psa_connect(ETSS_GENERATE_RANDOM_NUMBER_SID,
                         ETSS_GENERATE_RANDOM_NUMBER_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return ETSS_ERR_GENERIC_ERROR;
    }
    status = psa_call(handle, PSA_IPC_CALL, NULL, 0, out_vec,
                      IOVEC_LEN(out_vec));
    psa_close(handle);
    return (etss_err_t)status;
}

etss_err_t tfm_etss_mc_increment(uint8_t mc_id)
{
    psa_status_t status;
    psa_handle_t handle;

    psa_invec in_vec[] = {
        { .base = &mc_id, .len = sizeof(mc_id) }
    };
    handle = psa_connect(ETSS_MC_INCREMENT_SID, ETSS_MC_INCREMENT_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return ETSS_ERR_GENERIC_ERROR;
    }
    status = psa_call(handle, PSA_IPC_CALL, in_vec, IOVEC_LEN(in_vec), NULL, 0);
    psa_close(handle);
    return (etss_err_t)status;
}

etss_err_t tfm_etss_mc_get(uint8_t mc_id, uint8_t *buf, uint32_t buf_size)
{
    psa_status_t status;
    psa_handle_t handle;

    psa_invec in_vec[] = {
        { .base = &mc_id, .len = sizeof(mc_id) }
    };
    psa_outvec out_vec[] = {
        { .base = buf, .len = buf_size }
    };
    handle = psa_connect(ETSS_MC_GET_SID, ETSS_MC_GET_VERSION);
    if (!PSA_HANDLE_IS_VALID(handle)) {
        return ETSS_ERR_GENERIC_ERROR;
    }
    status = psa_call(handle, PSA_IPC_CALL, in_vec, IOVEC_LEN(in_vec), out_vec,
                      IOVEC_LEN(out_vec));
    psa_close(handle);
    return (etss_err_t)status;
}
