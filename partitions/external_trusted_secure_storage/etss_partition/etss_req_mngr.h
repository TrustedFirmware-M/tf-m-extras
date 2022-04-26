/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __ETSS_REQ_MNGR_H__
#define __ETSS_REQ_MNGR_H__

#include <stddef.h>
#include "psa/client.h"
#include "etss/etss_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Reads asset data from the caller.
 *
 * \param[out] buf        Buffer to copy the data to
 * \param[in]  num_bytes  Number of bytes to copy
 *
 * \return Number of bytes copied
 */
size_t etss_req_mngr_read(uint8_t *buf, size_t num_bytes);

/**
 * \brief Writes asset data to the caller.
 *
 * \param[in] buf        Buffer to copy the data from
 * \param[in] num_bytes  Number of bytes to copy
 */
void etss_req_mngr_write(const uint8_t *buf, size_t num_bytes);

#ifdef __cplusplus
}
#endif

#endif /* __ETSS_REQ_MNGR_H__ */
