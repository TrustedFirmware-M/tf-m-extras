/*
 * (c) 2023-2026, Infineon Technologies AG, or an affiliate of Infineon
 * Technologies AG. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "ifx_se_syscall.h"
#include "coverity_check.h"
#include "psa/service.h"
#include "psa_manifest/pid.h"
#include "psa_manifest/ifx_se_ipc_service.h"


psa_status_t ifx_se_ipc_service_sfn(const psa_msg_t *msg)
{
    size_t num;
    ifx_se_fih_uint cmd;
    ifx_se_fih_uint group;
    psa_status_t status;
    ifx_se_status_t se_status;

    /* IFX_SE_IPC_SERVICE - denies access by default, because it can't be
     * recursive call. */
    ifx_se_fih_uint allowed_client_id = IFX_SE_FIH_UINT_INIT((uint32_t)IFX_SE_IPC_SERVICE);
    ifx_se_fih_uint client_id = IFX_SE_FIH_UINT_INIT((uint32_t)msg->client_id);

    TFM_COVERITY_DEVIATE_LINE(MISRA_C_2023_Rule_12_1, "SE_RT_PACKET_MAX_SIZE defined externally, cannot change it")
    static uint32_t ifx_se_packet[SE_RT_PACKET_MAX_SIZE];

    if (msg->type != 0) {
        /* Unexpected request type */
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Validate arguments */
    TFM_COVERITY_DEVIATE_LINE(MISRA_C_2023_Rule_12_1, "SE_RT_PACKET_MIN_SIZE defined externally, cannot change it")
    if ((msg->in_size[0] < (SE_RT_PACKET_MIN_SIZE * sizeof(uint32_t))) ||
        (msg->in_size[0] > sizeof(ifx_se_packet)) ||
        (msg->out_size[0] != sizeof(se_status))) {
        /* The size of one of the arguments is incorrect */
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Read IFX SE IPC packet */
    num = psa_read(msg->handle, 0, ifx_se_packet, msg->in_size[0]);
    if (num != msg->in_size[0]) {
        return PSA_ERROR_GENERIC_ERROR;
    }

    /* Get command ID */
    TFM_COVERITY_DEVIATE_LINE(MISRA_C_2023_Rule_11_3, "Intentional pointer type conversion");
    cmd = SE_RT_PARAMS_GET_CMD(ifx_se_packet);

    /* Get command group ID */
    group = IFX_SE_SYSCALL_GET_GROUP(cmd);

    /* Get allowed client ID based on command group ID */
    if (ifx_se_fih_uint_eq(cmd, IFX_SE_SYSCALL_PSA_GET_RANDOM)) {
        /* Allow to access random generator from any partition */
        allowed_client_id = client_id;
    }
#ifdef TFM_PARTITION_CRYPTO
    else if (ifx_se_fih_uint_eq(group,
                         IFX_SE_SYSCALL_GROUP(IFX_SE_SYSCALL_GROUP_PSA_CRYPTO))) {
        /* PSA Crypto interface for Crypto partition only */
        allowed_client_id = ifx_se_fih_uint_encode(TFM_SP_CRYPTO);
    }
#endif /* TFM_PARTITION_CRYPTO */
#ifdef TFM_PARTITION_PLATFORM
    else if (ifx_se_fih_uint_eq(group,
                         IFX_SE_SYSCALL_GROUP(IFX_SE_SYSCALL_GROUP_RB_COUNTER))) {
        /* Rollback counter for platform partition */
        allowed_client_id = ifx_se_fih_uint_encode(TFM_SP_PLATFORM);
    }
#endif /* TFM_PARTITION_PLATFORM */
#ifdef TFM_PARTITION_INITIAL_ATTESTATION
    else if (ifx_se_fih_uint_eq(group,
                         IFX_SE_SYSCALL_GROUP(IFX_SE_SYSCALL_GROUP_ATTESTATION))) {
        /* Initial attestation interface for Initial attestation partition only */
        allowed_client_id = ifx_se_fih_uint_encode(TFM_SP_INITIAL_ATTESTATION);
    }
#endif /* TFM_PARTITION_INITIAL_ATTESTATION */
    else {
        return PSA_ERROR_NOT_PERMITTED;
    }
    /* Execute request for allowed client */
    if (ifx_se_fih_uint_eq(allowed_client_id, client_id)) {
        /* Call ifx_se_syscall_builtin */
        se_status = ifx_se_syscall_builtin(ifx_se_fih_ptr_encode(ifx_se_packet), NULL);

        /* Write status */
        psa_write(msg->handle, 0, (void *)&se_status, sizeof(se_status));
        status = PSA_SUCCESS;
    }
    else {
        /* Invalid client - deny access to service function */
        status = PSA_ERROR_NOT_PERMITTED;
    }

    /* Clear local packet */
    memset(ifx_se_packet, 0, msg->in_size[0]);

    return status;
}

psa_status_t ifx_se_ipc_service_entry(void)
{
    return PSA_SUCCESS;
}
