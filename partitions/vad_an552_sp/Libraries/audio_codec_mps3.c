/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "audio_codec_mps3.h"
#include "i2c_sbcon_drv.h"
#include "audio_i2s_mps3_drv.h"
#include "timeout.h"

#define CHIP_ADDR_WRITE     0x96
#define CHIP_ADDR_READ      0x97

/**
 * \brief CS42L52 Audio Codec registers
 */
#define AUDIO_CODEC_MPS3_CHIP_ID     0x01 /*!< Chip ID and Revision Register */
#define AUDIO_CODEC_MPS3_PWR_CTRL1   0x02 /*!< Power Control 1 */
#define AUDIO_CODEC_MPS3_PWR_CTRL2   0x03 /*!< Power Control 2 */
#define AUDIO_CODEC_MPS3_PWR_CTRL3   0x04 /*!< Power Control 3 */
#define AUDIO_CODEC_MPS3_CLK_CTRL    0x05 /*!< Clocking Control */
#define AUDIO_CODEC_MPS3_INT_CTRL1   0x06 /*!< Interface Control 1 */
#define AUDIO_CODEC_MPS3_INT_CTRL2   0x07 /*!< Interface Control 2 */
#define AUDIO_CODEC_MPS3_INPUT_A     0x08 /*!< Input x Select: ADCA and PGAA */
#define AUDIO_CODEC_MPS3_INPUT_B     0x09 /*!< Input x Select: ADCB and PGAB */
#define AUDIO_CODEC_MPS3_AMP_A       0x10 /*!< MICx Amp Control:MIC A */
#define AUDIO_CODEC_MPS3_AMP_B       0x11 /*!< MICx Amp Control:MIC B */
#define AUDIO_CODEC_MPS3_MISC_CTRL   0x0E /*!< Miscellaneous Controls */

static void audio_codec_mps3_write(struct i2c_sbcon_dev_t *i2c_sbcon_dev,
                                   uint8_t map_byte, uint8_t data)
{
    uint32_t i;
    uint8_t to_write[2];

    to_write[0] = map_byte;
    to_write[1] = data;
    i2c_sbcon_master_transmit(
                        i2c_sbcon_dev, CHIP_ADDR_WRITE, to_write, 2, 0, &i);
}

static uint8_t audio_codec_mps3_read(struct i2c_sbcon_dev_t *i2c_sbcon_dev,
                                     uint8_t map_byte)
{
    uint32_t i;
    uint8_t data;

    i2c_sbcon_master_transmit(
                        i2c_sbcon_dev, CHIP_ADDR_WRITE, &map_byte, 1, 0, &i);
    i2c_sbcon_master_receive(i2c_sbcon_dev, CHIP_ADDR_READ, &data, 1, 0, &i);

    return data;
}

enum audio_codec_mps3_error_t audio_codec_mps3_init(
                                    struct i2c_sbcon_dev_t *i2c_sbcon_dev,
                                    struct audio_i2s_mps3_dev_t *audio_i2s_mps3_dev)
{
    uint8_t reg_32;

    i2c_sbcon_init(i2c_sbcon_dev, WAIT_US_FREQ_HZ);
    audio_i2s_mps3_set_codec_reset(audio_i2s_mps3_dev);
    wait_ms(1);

    audio_i2s_mps3_clear_codec_reset(audio_i2s_mps3_dev);
    wait_ms(1);

    /* Initialization with values given in the Reference Manual */
    audio_codec_mps3_write(i2c_sbcon_dev, 0x00, 0x99);
    audio_codec_mps3_write(i2c_sbcon_dev, 0x3E, 0xBA);
    audio_codec_mps3_write(i2c_sbcon_dev, 0x47, 0x80);
    reg_32 = audio_codec_mps3_read(i2c_sbcon_dev, 0x32);
    audio_codec_mps3_write(i2c_sbcon_dev, 0x32, reg_32 | 0x80);
    audio_codec_mps3_write(i2c_sbcon_dev, 0x32, reg_32 & 0x7F);
    audio_codec_mps3_write(i2c_sbcon_dev, 0x00, 0x00);
    wait_ms(1);

    /* Single-speed mode */
    audio_codec_mps3_write(i2c_sbcon_dev, AUDIO_CODEC_MPS3_CLK_CTRL, 0x20);
    /* ADC charge pump and PGA & ADC channels powered up */
    audio_codec_mps3_write(i2c_sbcon_dev, AUDIO_CODEC_MPS3_PWR_CTRL1, 0x00);
    /* MIC powered up */
    audio_codec_mps3_write(i2c_sbcon_dev, AUDIO_CODEC_MPS3_PWR_CTRL2, 0x00);
    /* Headphone and Speaker channel always on */
    audio_codec_mps3_write(i2c_sbcon_dev, AUDIO_CODEC_MPS3_PWR_CTRL3, 0xAA);
    /* Select analog input for PGA AIN4A and AIN4B */
    audio_codec_mps3_write(i2c_sbcon_dev, AUDIO_CODEC_MPS3_INPUT_A, 0x90);
    audio_codec_mps3_write(i2c_sbcon_dev, AUDIO_CODEC_MPS3_INPUT_B, 0x90);
    /* Select MIC inputs and sets microphone pre-amplifier 32 dB */
    audio_codec_mps3_write(i2c_sbcon_dev, AUDIO_CODEC_MPS3_AMP_A, 0x5F);
    audio_codec_mps3_write(i2c_sbcon_dev, AUDIO_CODEC_MPS3_AMP_B, 0x5F);
    /* De-emphasis filter enabled */
    audio_codec_mps3_write(i2c_sbcon_dev, AUDIO_CODEC_MPS3_MISC_CTRL, 0x04);
    wait_ms(1);

    return AUDIO_CODEC_MPS3_ERR_NONE;
}
