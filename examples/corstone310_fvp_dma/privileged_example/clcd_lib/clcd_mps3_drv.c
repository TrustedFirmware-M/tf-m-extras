/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "clcd_mps3_drv.h"
#include "clcd_mps3_reg_map.h"

/**
 * \brief CLCD CHAR_RAW Register bit fields
 */
 #define CLCD_MPS3_ACCESS_COMPLETE_OFF               0u
    /*!< Color CLCD CHAR_RAW Register Access complete flag bit field offset */

/**
 * \brief CLCD CHAR_STAT Register bit fields
 */
 #define CLCD_MPS3_STATUS_OFF               0u
    /*!< Color CLCD CHAR_STAT Register state of Access complete ANDed with the
         CHAR_MASK bit field offset */

/**
 * \brief CLCD Miscellaneuos Control Register bit fields
 */
 #define CLCD_MPS3_CS_OFF               0u
    /*!< Color CLCD CHAR_MISC Register Chip select bit field offset */
 #define CLCD_MPS3_WR_OFF               1u
    /*!< Color CLCD CHAR_MISC Register Write enable bit field offset */
 #define CLCD_MPS3_RESET_OFF            3u
    /*!< Color CLCD CHAR_MISC Register Reset bit field offset */
 #define CLCD_MPS3_RS_OFF               4u
    /*!< Color CLCD CHAR_MISC Register Register select bit field offset */
 #define CLCD_MPS3_RD_OFF               5u
    /*!< Color CLCD CHAR_MISC Register Read enable bit field offset */
 #define CLCD_MPS3_BL_OFF               6u
    /*!< Color CLCD CHAR_MISC Register Backlight bit field offset */

void clcd_mps3_write_command(struct clcd_mps3_dev_t* dev,
                             uint32_t value)
{
    struct clcd_mps3_reg_map_t* p_clcd =
                                (struct clcd_mps3_reg_map_t*)dev->cfg->base;
    p_clcd->char_com = value;
}

uint32_t clcd_mps3_read_busy(struct clcd_mps3_dev_t* dev)
{
    struct clcd_mps3_reg_map_t* p_clcd =
                                (struct clcd_mps3_reg_map_t*)dev->cfg->base;
    return p_clcd->char_com;
}

void clcd_mps3_write_data(struct clcd_mps3_dev_t* dev,
                             uint32_t value)
{
    struct clcd_mps3_reg_map_t* p_clcd =
                                (struct clcd_mps3_reg_map_t*)dev->cfg->base;
    p_clcd->char_dat = value;
}

uint32_t clcd_mps3_read_data(struct clcd_mps3_dev_t* dev)
{
    struct clcd_mps3_reg_map_t* p_clcd =
                                (struct clcd_mps3_reg_map_t*)dev->cfg->base;
    return p_clcd->char_dat;
}

uint8_t clcd_mps3_read_rd(struct clcd_mps3_dev_t* dev)
{
    struct clcd_mps3_reg_map_t* p_clcd =
                                (struct clcd_mps3_reg_map_t*)dev->cfg->base;
    return (uint8_t)p_clcd->char_rd;
}

void clcd_mps3_clear_access_complete(struct clcd_mps3_dev_t* dev)
{
    struct clcd_mps3_reg_map_t* p_clcd =
                                (struct clcd_mps3_reg_map_t*)dev->cfg->base;
    p_clcd->char_raw &= ~(0x1UL << CLCD_MPS3_ACCESS_COMPLETE_OFF);
}

bool clcd_mps3_is_access_complete_set(struct clcd_mps3_dev_t* dev)
{
    struct clcd_mps3_reg_map_t* p_clcd =
                                (struct clcd_mps3_reg_map_t*)dev->cfg->base;
    return (bool)((p_clcd->char_raw >> CLCD_MPS3_ACCESS_COMPLETE_OFF) & 0x1UL);
}

void clcd_mps3_enable_write_interrupt(struct clcd_mps3_dev_t* dev)
{
    struct clcd_mps3_reg_map_t* p_clcd =
                                (struct clcd_mps3_reg_map_t*)dev->cfg->base;
    p_clcd->char_raw |= 0x1UL;
}

void clcd_mps3_disable_write_interrupt(struct clcd_mps3_dev_t* dev)
{
    struct clcd_mps3_reg_map_t* p_clcd =
                                (struct clcd_mps3_reg_map_t*)dev->cfg->base;
    p_clcd->char_raw &= ~(0x1UL);
}

uint32_t clcd_mps3_read_status(struct clcd_mps3_dev_t* dev){
    struct clcd_mps3_reg_map_t* p_clcd =
                                (struct clcd_mps3_reg_map_t*)dev->cfg->base;
    return p_clcd->char_stat;
}

uint32_t clcd_mps3_read_misc(struct clcd_mps3_dev_t* dev)
{
    struct clcd_mps3_reg_map_t* p_clcd =
                                (struct clcd_mps3_reg_map_t*)dev->cfg->base;
    return p_clcd->char_misc;
}

void clcd_mps3_write_misc(struct clcd_mps3_dev_t* dev,
                             uint32_t value)
{
    struct clcd_mps3_reg_map_t* p_clcd =
                                (struct clcd_mps3_reg_map_t*)dev->cfg->base;
    p_clcd->char_misc = value;
}

void clcd_mps3_set_bl(struct clcd_mps3_dev_t* dev)
{
    struct clcd_mps3_reg_map_t* p_clcd =
                                (struct clcd_mps3_reg_map_t*)dev->cfg->base;
    p_clcd->char_misc |= (0x1UL << CLCD_MPS3_BL_OFF);
}

void clcd_mps3_clear_bl(struct clcd_mps3_dev_t* dev)
{
    struct clcd_mps3_reg_map_t* p_clcd =
                                (struct clcd_mps3_reg_map_t*)dev->cfg->base;
    p_clcd->char_misc &= ~(0x1UL << CLCD_MPS3_BL_OFF);
}

void clcd_mps3_set_rd(struct clcd_mps3_dev_t* dev)
{
    struct clcd_mps3_reg_map_t* p_clcd =
                                (struct clcd_mps3_reg_map_t*)dev->cfg->base;
    p_clcd->char_misc |= (0x1UL << CLCD_MPS3_RD_OFF);
}

void clcd_mps3_clear_rd(struct clcd_mps3_dev_t* dev)
{
    struct clcd_mps3_reg_map_t* p_clcd =
                                (struct clcd_mps3_reg_map_t*)dev->cfg->base;
    p_clcd->char_misc &= ~(0x1UL << CLCD_MPS3_RD_OFF);
}

void clcd_mps3_set_rs(struct clcd_mps3_dev_t* dev)
{
    struct clcd_mps3_reg_map_t* p_clcd =
                                (struct clcd_mps3_reg_map_t*)dev->cfg->base;
    p_clcd->char_misc |= (0x1UL << CLCD_MPS3_RS_OFF);
}

void clcd_mps3_clear_rs(struct clcd_mps3_dev_t* dev)
{
    struct clcd_mps3_reg_map_t* p_clcd =
                                (struct clcd_mps3_reg_map_t*)dev->cfg->base;
    p_clcd->char_misc &= ~(0x1UL << CLCD_MPS3_RS_OFF);
}

void clcd_mps3_set_reset(struct clcd_mps3_dev_t* dev)
{
    struct clcd_mps3_reg_map_t* p_clcd =
                                (struct clcd_mps3_reg_map_t*)dev->cfg->base;
    p_clcd->char_misc |= (0x1UL << CLCD_MPS3_RESET_OFF);
}

void clcd_mps3_clear_reset(struct clcd_mps3_dev_t* dev)
{
    struct clcd_mps3_reg_map_t* p_clcd =
                                (struct clcd_mps3_reg_map_t*)dev->cfg->base;
    p_clcd->char_misc &= ~(0x1UL << CLCD_MPS3_RESET_OFF);
}

void clcd_mps3_set_wr(struct clcd_mps3_dev_t* dev)
{
    struct clcd_mps3_reg_map_t* p_clcd =
                                (struct clcd_mps3_reg_map_t*)dev->cfg->base;
    p_clcd->char_misc |= (0x1UL << CLCD_MPS3_WR_OFF);
}

void clcd_mps3_clear_wr(struct clcd_mps3_dev_t* dev)
{
    struct clcd_mps3_reg_map_t* p_clcd =
                                (struct clcd_mps3_reg_map_t*)dev->cfg->base;
    p_clcd->char_misc &= ~(0x1UL << CLCD_MPS3_WR_OFF);
}

void clcd_mps3_set_cs(struct clcd_mps3_dev_t* dev)
{
    struct clcd_mps3_reg_map_t* p_clcd =
                                (struct clcd_mps3_reg_map_t*)dev->cfg->base;
    p_clcd->char_misc |= (0x1UL << CLCD_MPS3_CS_OFF);
}

void clcd_mps3_clear_cs(struct clcd_mps3_dev_t* dev)
{
    struct clcd_mps3_reg_map_t* p_clcd =
                                (struct clcd_mps3_reg_map_t*)dev->cfg->base;
    p_clcd->char_misc &= ~(0x1UL << CLCD_MPS3_CS_OFF);
}
