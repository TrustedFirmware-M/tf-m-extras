/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef _ETSS_DEFS_H_
#define _ETSS_DEFS_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file etss_defs.h
 *
 * \brief This file describes the ETSS errors
 *
 */

/**
 *
 * \brief etss service error types
 *
 */
typedef int32_t etss_err_t;

#define ETSS_SUCCESS                   ((etss_err_t)0)

#define ETSS_ERR_PROGRAMMER_ERROR      ((etss_err_t)-129)
#define ETSS_ERR_CONNECTION_REFUSED    ((etss_err_t)-130)
#define ETSS_ERR_CONNECTION_BUSY       ((etss_err_t)-131)
#define ETSS_ERR_GENERIC_ERROR         ((etss_err_t)-132)
#define ETSS_ERR_NOT_PERMITTED         ((etss_err_t)-133)
#define ETSS_ERR_NOT_SUPPORTED         ((etss_err_t)-134)
#define ETSS_ERR_INVALID_ARGUMENT      ((etss_err_t)-135)
#define ETSS_ERR_INVALID_HANDLE        ((etss_err_t)-136)
#define ETSS_ERR_BAD_STATE             ((etss_err_t)-137)
#define ETSS_ERR_BUFFER_TOO_SMALL      ((etss_err_t)-138)
#define ETSS_ERR_ALREADY_EXISTS        ((etss_err_t)-139)
#define ETSS_ERR_DOES_NOT_EXIST        ((etss_err_t)-140)
#define ETSS_ERR_INSUFFICIENT_MEMORY   ((etss_err_t)-141)
#define ETSS_ERR_INSUFFICIENT_STORAGE  ((etss_err_t)-142)
#define ETSS_ERR_INSUFFICIENT_DATA     ((etss_err_t)-143)
#define ETSS_ERR_SERVICE_FAILURE       ((etss_err_t)-144)
#define ETSS_ERR_COMMUNICATION_FAILURE ((etss_err_t)-145)
#define ETSS_ERR_STORAGE_FAILURE       ((etss_err_t)-146)
#define ETSS_ERR_HARDWARE_FAILURE      ((etss_err_t)-147)
#define ETSS_ERR_INVALID_SIGNATURE     ((etss_err_t)-149)
#define ETSS_ERR_DEPENDENCY_NEEDED     ((etss_err_t)-156)
#define ETSS_ERR_CURRENTLY_INSTALLING  ((etss_err_t)-157)
#define ETSS_ERR_SF_UNPROVISIONED      ((etss_err_t)-158)
#define ETSS_ERR_SF_INIT               ((etss_err_t)-159)
#define ETSS_ERR_SF_PROVISION          ((etss_err_t)-160)

/* Invalid UID */
#define ETSS_INVALID_UID               0

#ifdef __cplusplus
}
#endif

#endif /* _ETSS_DEFS_H_ */
