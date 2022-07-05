/*
 * Copyright (c) 2020-2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __TFM_EXAMPLE_PARTITION_API_H__
#define __TFM_EXAMPLE_PARTITION_API_H__

#include <stdint.h>

#include "psa/error.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Makes a request to the example service.
 *
 * \param[in] arg  Example parameter
 *
 * \return Returns error code as specified in \ref psa_status_t
 */
psa_status_t tfm_example_service(uint32_t arg);

#ifdef __cplusplus
}
#endif

#endif /* __TFM_EXAMPLE_PARTITION_API_H__ */
