/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "smsc9220_eth_drv.h"
#include "platform_base_address.h"
#include "platform_eth_dev.h"

static struct smsc9220_eth_dev_cfg_t SMSC9220_ETH_DEV_CFG_NS = {
    .base = ETHERNET_BASE_NS
};

static struct smsc9220_eth_dev_data_t SMSC9220_ETH_DEV_DATA_NS = {
    .state = 0,
    .wait_ms = 0,
    .ongoing_packet_length = 0,
    .ongoing_packet_length_sent = 0,
};

struct smsc9220_eth_dev_t SMSC9220_ETH_DEV_NS = {
    .cfg = &(SMSC9220_ETH_DEV_CFG_NS),
    .data = &(SMSC9220_ETH_DEV_DATA_NS),
};
