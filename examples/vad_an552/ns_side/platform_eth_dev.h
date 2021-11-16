/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __PLATFORM_ETH_DEV_H__
#define __PLATFORM_ETH_DEV_H__

#include "smsc9220_eth_drv.h"

#define ETH_DEV             SMSC9220_ETH_DEV_NS

#ifdef __cplusplus
extern "C" {
#endif

extern struct smsc9220_eth_dev_t SMSC9220_ETH_DEV_NS;

#ifdef __cplusplus
}
#endif

#endif /* __PLATFORM_ETH_DEV_H__ */
