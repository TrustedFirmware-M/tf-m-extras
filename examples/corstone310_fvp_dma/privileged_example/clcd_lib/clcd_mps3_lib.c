/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "clcd_mps3_lib.h"
#include "clcd_mps3_drv.h"
#include "timeout.h"

#define MAX_WIDTH       320
#define MAX_HEIGHT      240
#define CLR_BLACK       0x0000

static enum clcd_mps3_lib_error_t clcd_mps3_lib_write_command(struct clcd_mps3_dev_t* dev,
                                                            uint8_t value)
{
    clcd_mps3_clear_cs(dev);
    wait_us(1);
    clcd_mps3_write_command(dev, value);
    clcd_mps3_set_cs(dev);
    return CLCD_MPS3_LIB_ERR_NONE;
}

static enum clcd_mps3_lib_error_t clcd_mps3_lib_write_data(struct clcd_mps3_dev_t* dev,
                                                        uint16_t *data, uint32_t size)
{
    int i;
    clcd_mps3_clear_cs(dev);
    for (i = 0; i < size; i++) {
        clcd_mps3_write_data(dev, data[i] >>8);
        clcd_mps3_write_data(dev, data[i] & 0xFF);
    }
    clcd_mps3_set_cs(dev);
    return CLCD_MPS3_LIB_ERR_NONE;
}

static enum clcd_mps3_lib_error_t clcd_mps3_lib_write_to_register(struct clcd_mps3_dev_t* dev,
                                                           uint8_t reg,
                                                           uint16_t value)
{
    clcd_mps3_clear_cs(dev);
    wait_us(1);
    clcd_mps3_write_command(dev, reg);
    clcd_mps3_write_data(dev, value >>8);
    clcd_mps3_write_data(dev, value & 0xFF);
    clcd_mps3_set_cs(dev);
    return CLCD_MPS3_LIB_ERR_NONE;
}

static enum clcd_mps3_lib_error_t clcd_mps3_lib_clear_window(struct clcd_mps3_dev_t* dev,
                                                  uint32_t pos_horizontal,
                                                  uint32_t pos_vertical,
                                                  uint32_t width,
                                                  uint32_t height)
{
    uint32_t i;

    clcd_mps3_lib_set_window(dev, pos_horizontal, pos_vertical, width, height);

    clcd_mps3_lib_write_command(dev, 0x22);
    clcd_mps3_clear_cs(dev);
    for (i = 0; i < (width*height); i++) {
        clcd_mps3_write_data(dev, CLR_BLACK >> 8);
        clcd_mps3_write_data(dev, CLR_BLACK & 0xFF);
    }

    clcd_mps3_set_cs(dev);

    return CLCD_MPS3_LIB_ERR_NONE;
}

enum clcd_mps3_lib_error_t clcd_mps3_lib_set_window(struct clcd_mps3_dev_t* dev,
                                               uint32_t pos_horizontal,
                                               uint32_t pos_vertical,
                                               uint32_t width, uint32_t height)
{
    uint32_t pos_horizontal_end, pos_vertical_end;

    pos_horizontal_end = pos_horizontal + width - 1;
    pos_vertical_end = pos_vertical + height - 1;

    clcd_mps3_lib_write_to_register(dev, 0x02, pos_horizontal >> 8);
    clcd_mps3_lib_write_to_register(dev, 0x03, pos_horizontal & 0xFF);
    clcd_mps3_lib_write_to_register(dev, 0x04, pos_horizontal_end >> 8);
    clcd_mps3_lib_write_to_register(dev, 0x05, pos_horizontal_end & 0xFF);

    clcd_mps3_lib_write_to_register(dev, 0x06, pos_vertical >> 8);
    clcd_mps3_lib_write_to_register(dev, 0x07, pos_vertical & 0xFF);
    clcd_mps3_lib_write_to_register(dev, 0x08, pos_vertical_end >> 8);
    clcd_mps3_lib_write_to_register(dev, 0x09, pos_vertical_end & 0xFF);

    return CLCD_MPS3_LIB_ERR_NONE;
}

enum clcd_mps3_lib_error_t clcd_mps3_init(struct clcd_mps3_dev_t* dev)
{
    clcd_mps3_set_cs(dev);
    clcd_mps3_set_reset(dev);
    clcd_mps3_clear_cs(dev);
    wait_ms(1);

    clcd_mps3_clear_reset(dev);
    wait_ms(1);
    clcd_mps3_set_reset(dev);
    wait_ms(1);

    /* Driving ability settings ---------------------------------------------*/
    clcd_mps3_lib_write_to_register(dev, 0xEA, 0x00);
    clcd_mps3_lib_write_to_register(dev, 0xEB, 0x20);
    clcd_mps3_lib_write_to_register(dev, 0xEC, 0x0C);
    clcd_mps3_lib_write_to_register(dev, 0xED, 0xC7);
    clcd_mps3_lib_write_to_register(dev, 0xE8, 0x38);
    clcd_mps3_lib_write_to_register(dev, 0xE9, 0x10);
    clcd_mps3_lib_write_to_register(dev, 0xF1, 0x01);
    clcd_mps3_lib_write_to_register(dev, 0xF2, 0x10);

    /* Adjust the Gamma Curve -----------------------------------------------*/
    clcd_mps3_lib_write_to_register(dev, 0x40, 0x01);
    clcd_mps3_lib_write_to_register(dev, 0x41, 0x00);
    clcd_mps3_lib_write_to_register(dev, 0x42, 0x00);
    clcd_mps3_lib_write_to_register(dev, 0x43, 0x10);
    clcd_mps3_lib_write_to_register(dev, 0x44, 0x0E);
    clcd_mps3_lib_write_to_register(dev, 0x45, 0x24);
    clcd_mps3_lib_write_to_register(dev, 0x46, 0x04);
    clcd_mps3_lib_write_to_register(dev, 0x47, 0x50);
    clcd_mps3_lib_write_to_register(dev, 0x48, 0x02);
    clcd_mps3_lib_write_to_register(dev, 0x49, 0x13);
    clcd_mps3_lib_write_to_register(dev, 0x4A, 0x19);
    clcd_mps3_lib_write_to_register(dev, 0x4B, 0x19);
    clcd_mps3_lib_write_to_register(dev, 0x4C, 0x16);

    clcd_mps3_lib_write_to_register(dev, 0x50, 0x1B);
    clcd_mps3_lib_write_to_register(dev, 0x51, 0x31);
    clcd_mps3_lib_write_to_register(dev, 0x52, 0x2F);
    clcd_mps3_lib_write_to_register(dev, 0x53, 0x3F);
    clcd_mps3_lib_write_to_register(dev, 0x54, 0x3F);
    clcd_mps3_lib_write_to_register(dev, 0x55, 0x3E);
    clcd_mps3_lib_write_to_register(dev, 0x56, 0x2F);
    clcd_mps3_lib_write_to_register(dev, 0x57, 0x7B);
    clcd_mps3_lib_write_to_register(dev, 0x58, 0x09);
    clcd_mps3_lib_write_to_register(dev, 0x59, 0x06);
    clcd_mps3_lib_write_to_register(dev, 0x5A, 0x06);
    clcd_mps3_lib_write_to_register(dev, 0x5B, 0x0C);
    clcd_mps3_lib_write_to_register(dev, 0x5C, 0x1D);
    clcd_mps3_lib_write_to_register(dev, 0x5D, 0xCC);

    /* Power voltage setting ------------------------------------------------*/
    clcd_mps3_lib_write_to_register(dev, 0x1B, 0x1B);
    clcd_mps3_lib_write_to_register(dev, 0x1A, 0x01);
    clcd_mps3_lib_write_to_register(dev, 0x24, 0x2F);
    clcd_mps3_lib_write_to_register(dev, 0x25, 0x57);
    clcd_mps3_lib_write_to_register(dev, 0x23, 0x88);

    /* Power on setting -----------------------------------------------------*/
    clcd_mps3_lib_write_to_register(dev, 0x18, 0x36);
    clcd_mps3_lib_write_to_register(dev, 0x19, 0x01);
    clcd_mps3_lib_write_to_register(dev, 0x01, 0x00);
    clcd_mps3_lib_write_to_register(dev, 0x1F, 0x88);
    wait_us(20);
    clcd_mps3_lib_write_to_register(dev, 0x1F, 0x82);
    wait_us(5);
    clcd_mps3_lib_write_to_register(dev, 0x1F, 0x92);
    wait_us(5);
    clcd_mps3_lib_write_to_register(dev, 0x1F, 0xD2);
    wait_us(5);

    /* Color selection ------------------------------------------------------*/
    clcd_mps3_lib_write_to_register(dev, 0x17, 0x55);
    clcd_mps3_lib_write_to_register(dev, 0x00, 0x00);
    clcd_mps3_lib_write_to_register(dev, 0x16, 0xA8);

    /* Interface config -----------------------------------------------------*/
    clcd_mps3_lib_write_to_register(dev, 0x2F, 0x11);
    clcd_mps3_lib_write_to_register(dev, 0x31, 0x00);
    clcd_mps3_lib_write_to_register(dev, 0x32, 0x00);

    /* Display on setting ---------------------------------------------------*/
    clcd_mps3_lib_write_to_register(dev, 0x28, 0x38);
    wait_us(5);
    clcd_mps3_lib_write_to_register(dev, 0x28, 0x3C);

    /* Display scrolling settings -------------------------------------------*/
    clcd_mps3_lib_write_to_register(dev, 0x0E, 0x00);
    clcd_mps3_lib_write_to_register(dev, 0x0F, 0x00);
    clcd_mps3_lib_write_to_register(dev, 0x10, 320 >> 8);
    clcd_mps3_lib_write_to_register(dev, 0x11, 320 &  0xFF);
    clcd_mps3_lib_write_to_register(dev, 0x12, 0x00);
    clcd_mps3_lib_write_to_register(dev, 0x13, 0x00);

    clcd_mps3_set_bl(dev);

    clcd_mps3_lib_clear_window(dev, 0, 0, MAX_WIDTH, MAX_HEIGHT);

    return CLCD_MPS3_LIB_ERR_NONE;
}


enum clcd_mps3_lib_error_t clcd_mps3_display_image(struct clcd_mps3_dev_t* dev,
                                                   uint32_t pos_horizontal,
                                                   uint32_t pos_vertical,
                                                   uint32_t width,
                                                   uint32_t height,
                                                   uint16_t *bitmap)
{
    uint16_t *bitmap_ptr = bitmap;

    clcd_mps3_lib_set_window(dev, pos_horizontal, pos_vertical, width, height);
    clcd_mps3_lib_write_command(dev, 0x22);
    clcd_mps3_lib_write_data(dev, bitmap_ptr, height*width);

    return CLCD_MPS3_LIB_ERR_NONE;
}
