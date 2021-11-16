/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "audio_i2s_mps3_drv.h"

/**
 * \brief Audio I2S register map structure
 */
struct audio_i2s_mps3_reg_map_t{
        /* Offset: 0x000 (R/W) Control Register    */
    volatile uint32_t control;
        /* Offset: 0x004 (R/W) Status Register    */
    volatile uint32_t status;
        /* Offset: 0x008 (R/W) Error Register    */
    volatile uint32_t error;
        /* Offset: 0x00C (R/W) Clock Divide Ratio Register    */
    volatile uint32_t divide;
        /* Offset: 0x010 (W) Transmit Buffer FIFO Data Register    */
    volatile uint32_t txbuf;
        /* Offset: 0x014 (R) Receive Buffer FIFO Data Register    */
    volatile uint32_t rxbuf;
        /*!< Offset: 0x018-0x2FF Reserved */
    volatile const uint32_t reserved[14];
        /* Offset: 0x300 (R/W) Integration Test Control Register    */
    volatile uint32_t itcr;
        /* Offset: 0x304 (R/W) Integration Test Input Register    */
    volatile uint32_t itip1;
        /* Offset: 0x308 (R/W) Integration Test Output Register    */
    volatile uint32_t itop1;
};

/**
 * \brief Audio I2S Control Register bit fields
 */
#define AUDIO_I2S_MPS3_CONTROL_TX_EN_OFF                 0u
    /*!< Audio I2S Control Register Tx Enable bit field offset */
#define AUDIO_I2S_MPS3_CONTROL_TX_INTREN_OFF             1u
    /*!< Audio I2S Control Register Tx Interrupt Enable bit field offset */
#define AUDIO_I2S_MPS3_CONTROL_RX_EN_OFF                 2u
    /*!< Audio I2S Control Register Rx Enable bit field offset */
#define AUDIO_I2S_MPS3_CONTROL_RX_INTREN_OFF             3u
    /*!< Audio I2S Control Register Rx Interrupt Enable bit field offset */
#define AUDIO_I2S_MPS3_CONTROL_TX_BUFF_IRQ_WATER_LVL_OFF 8u
    /*!< Audio I2S Control Register Tx Buffer Interrupt Water Level Offset */
#define AUDIO_I2S_MPS3_CONTROL_RX_BUFF_IRQ_WATER_LVL_OFF 12u
    /*!< Audio I2S Control Register Rx Buffer Interrupt Water Level Offset */
#define AUDIO_I2S_MPS3_CONTROL_FIFO_RESET_OFF            16u
    /*!< Audio I2S Control Register FIFO Reset bit field offset */
#define AUDIO_I2S_MPS3_CONTROL_CODEC_RESET_OFF           17u
    /*!< Audio I2S Control Register Audio Codec Reset bit field offset */

/**
 * \brief Audio I2S Status Register bit fields
 */
#define AUDIO_I2S_MPS3_STATUS_TXBUF_EMPTY_OFF             2u
    /*!< Audio I2S Status Register Tx Buffer Empty bit field offset */
#define AUDIO_I2S_MPS3_STATUS_TXBUF_FULL_OFF              3u
    /*!< Audio I2S Status Register Tx Buffer Full bit field offset */
#define AUDIO_I2S_MPS3_STATUS_RXBUF_EMPTY_OFF             4u
    /*!< Audio I2S Status Register Tx Buffer Empty bit field offset */
#define AUDIO_I2S_MPS3_STATUS_RXBUF_FULL_OFF              5u
    /*!< Audio I2S Status Register Tx Buffer Full bit field offset */

#define LRDIV_MAX_VALUE     0x3FF

void audio_i2s_mps3_set_codec_reset(struct audio_i2s_mps3_dev_t* dev)
{
    struct audio_i2s_mps3_reg_map_t* p_i2s =
                (struct audio_i2s_mps3_reg_map_t*)dev->cfg->base;
    p_i2s->control |= (1 << AUDIO_I2S_MPS3_CONTROL_CODEC_RESET_OFF);
}

void audio_i2s_mps3_set_fifo_reset(struct audio_i2s_mps3_dev_t* dev)
{
    struct audio_i2s_mps3_reg_map_t* p_i2s =
                (struct audio_i2s_mps3_reg_map_t*)dev->cfg->base;
    p_i2s->control |= (1 << AUDIO_I2S_MPS3_CONTROL_FIFO_RESET_OFF);
}

void audio_i2s_mps3_clear_codec_reset(struct audio_i2s_mps3_dev_t* dev)
{
    struct audio_i2s_mps3_reg_map_t* p_i2s = (struct audio_i2s_mps3_reg_map_t*)dev->cfg->base;
    p_i2s->control &= ~(1 << AUDIO_I2S_MPS3_CONTROL_CODEC_RESET_OFF);
}

void audio_i2s_mps3_clear_fifo_reset(struct audio_i2s_mps3_dev_t* dev)
{
    struct audio_i2s_mps3_reg_map_t* p_i2s = (struct audio_i2s_mps3_reg_map_t*)dev->cfg->base;
    p_i2s->control &= ~(1 <<  AUDIO_I2S_MPS3_CONTROL_FIFO_RESET_OFF);
}

enum audio_i2s_mps3_error_t audio_i2s_mps3_speed_config(struct audio_i2s_mps3_dev_t* dev, uint16_t lrdiv)
{
    struct audio_i2s_mps3_reg_map_t* p_i2s = (struct audio_i2s_mps3_reg_map_t*)dev->cfg->base;

    if ( lrdiv > LRDIV_MAX_VALUE ) {
        return AUDIO_I2S_MPS3_ERR_INVALID_ARG;
    }
    p_i2s->divide = lrdiv;
    return AUDIO_I2S_MPS3_ERR_NONE;
}

bool audio_i2s_mps3_is_rx_buffer_empty(struct audio_i2s_mps3_dev_t* dev)
{
    struct audio_i2s_mps3_reg_map_t* p_i2s = (struct audio_i2s_mps3_reg_map_t*)dev->cfg->base;
    return (bool)((p_i2s->status >> AUDIO_I2S_MPS3_STATUS_RXBUF_EMPTY_OFF) & 0x1);
}

bool audio_i2s_mps3_is_rx_buffer_full(struct audio_i2s_mps3_dev_t* dev)
{
    struct audio_i2s_mps3_reg_map_t* p_i2s = (struct audio_i2s_mps3_reg_map_t*)dev->cfg->base;
    return (bool)((p_i2s->status >> AUDIO_I2S_MPS3_STATUS_RXBUF_FULL_OFF) & 0x1);
}

bool audio_i2s_mps3_is_tx_buffer_empty(struct audio_i2s_mps3_dev_t* dev)
{
    struct audio_i2s_mps3_reg_map_t* p_i2s = (struct audio_i2s_mps3_reg_map_t*)dev->cfg->base;
    return (bool)((p_i2s->status >> AUDIO_I2S_MPS3_STATUS_TXBUF_EMPTY_OFF) & 0x1);
}

bool audio_i2s_mps3_is_tx_buffer_full(struct audio_i2s_mps3_dev_t* dev)
{
    struct audio_i2s_mps3_reg_map_t* p_i2s = (struct audio_i2s_mps3_reg_map_t*)dev->cfg->base;
    return (bool)((p_i2s->status >> AUDIO_I2S_MPS3_STATUS_TXBUF_FULL_OFF) & 0x1);
}

uint32_t audio_i2s_mps3_get_rxbuf(struct audio_i2s_mps3_dev_t* dev)
{
    struct audio_i2s_mps3_reg_map_t* p_i2s = (struct audio_i2s_mps3_reg_map_t*)dev->cfg->base;
    return p_i2s->rxbuf;
}

void audio_i2s_mps3_set_txbuf(struct audio_i2s_mps3_dev_t* dev, uint16_t left_channel,
                    uint16_t right_channel)
{
    struct audio_i2s_mps3_reg_map_t* p_i2s = (struct audio_i2s_mps3_reg_map_t*)dev->cfg->base;
    uint32_t sample = ((uint32_t)left_channel) << 16;
    sample += right_channel;
    p_i2s->txbuf = sample;
}

uint32_t audio_i2s_mps3_get_control(struct audio_i2s_mps3_dev_t* dev)
{
    struct audio_i2s_mps3_reg_map_t* p_i2s = (struct audio_i2s_mps3_reg_map_t*)dev->cfg->base;
    return p_i2s->control;
}

uint32_t audio_i2s_mps3_get_status(struct audio_i2s_mps3_dev_t* dev)
{
    struct audio_i2s_mps3_reg_map_t* p_i2s = (struct audio_i2s_mps3_reg_map_t*)dev->cfg->base;
    return p_i2s->status;
}

uint32_t audio_i2s_mps3_get_error(struct audio_i2s_mps3_dev_t* dev)
{
    struct audio_i2s_mps3_reg_map_t* p_i2s = (struct audio_i2s_mps3_reg_map_t*)dev->cfg->base;
    return p_i2s->error;
}

void audio_i2s_mps3_enable_rxbuf(struct audio_i2s_mps3_dev_t* dev)
{
    struct audio_i2s_mps3_reg_map_t* p_i2s = (struct audio_i2s_mps3_reg_map_t*)dev->cfg->base;
    p_i2s->control |= (1 << AUDIO_I2S_MPS3_CONTROL_RX_EN_OFF);
}

void audio_i2s_mps3_enable_rxinterrupt(struct audio_i2s_mps3_dev_t* dev)
{
    struct audio_i2s_mps3_reg_map_t* p_i2s = (struct audio_i2s_mps3_reg_map_t*)dev->cfg->base;
    p_i2s->control |= (1 << AUDIO_I2S_MPS3_CONTROL_RX_INTREN_OFF);
}

void audio_i2s_mps3_enable_txbuf(struct audio_i2s_mps3_dev_t* dev)
{
    struct audio_i2s_mps3_reg_map_t* p_i2s = (struct audio_i2s_mps3_reg_map_t*)dev->cfg->base;
    p_i2s->control |= (1 << AUDIO_I2S_MPS3_CONTROL_TX_EN_OFF);
}

void audio_i2s_mps3_enable_txinterrupt(struct audio_i2s_mps3_dev_t* dev)
{
    struct audio_i2s_mps3_reg_map_t* p_i2s = (struct audio_i2s_mps3_reg_map_t*)dev->cfg->base;
    p_i2s->control |= (1 <<  AUDIO_I2S_MPS3_CONTROL_TX_INTREN_OFF);
}

void audio_i2s_mps3_disable_rxbuf(struct audio_i2s_mps3_dev_t* dev)
{
    struct audio_i2s_mps3_reg_map_t* p_i2s = (struct audio_i2s_mps3_reg_map_t*)dev->cfg->base;
    p_i2s->control &= ~(1 <<  AUDIO_I2S_MPS3_CONTROL_RX_EN_OFF);
}

void audio_i2s_mps3_disable_rxinterrupt(struct audio_i2s_mps3_dev_t* dev)
{
    struct audio_i2s_mps3_reg_map_t* p_i2s = (struct audio_i2s_mps3_reg_map_t*)dev->cfg->base;
    p_i2s->control &= ~(1 <<  AUDIO_I2S_MPS3_CONTROL_RX_INTREN_OFF);
}

void audio_i2s_mps3_disable_txbuf(struct audio_i2s_mps3_dev_t* dev)
{
    struct audio_i2s_mps3_reg_map_t* p_i2s = (struct audio_i2s_mps3_reg_map_t*)dev->cfg->base;
    p_i2s->control &= ~(1 <<  AUDIO_I2S_MPS3_CONTROL_TX_EN_OFF);
}

void audio_i2s_mps3_disable_txinterrupt(struct audio_i2s_mps3_dev_t* dev)
{
    struct audio_i2s_mps3_reg_map_t* p_i2s = (struct audio_i2s_mps3_reg_map_t*)dev->cfg->base;
    p_i2s->control &= ~(1 <<  AUDIO_I2S_MPS3_CONTROL_TX_INTREN_OFF);
}

struct audio_i2s_mps3_sample_t read_sample(struct audio_i2s_mps3_dev_t* dev)
{
    struct audio_i2s_mps3_sample_t sample;
    uint32_t s = audio_i2s_mps3_get_rxbuf(dev);
    sample.right_channel = s & 0xFFFF;
    sample.left_channel = s >> 16;
    return sample;
}

void write_sample(struct audio_i2s_mps3_dev_t* dev, struct audio_i2s_mps3_sample_t sample)
{
    audio_i2s_mps3_set_txbuf(dev, sample.left_channel, sample.right_channel);
}

void audio_i2s_mps3_set_tx_buff_water_lvl(struct audio_i2s_mps3_dev_t* dev,
                                          uint8_t level){
    struct audio_i2s_mps3_reg_map_t* p_i2s = (struct audio_i2s_mps3_reg_map_t*)dev->cfg->base;
    p_i2s->control = (p_i2s->control & ~(0x7 << AUDIO_I2S_MPS3_CONTROL_TX_BUFF_IRQ_WATER_LVL_OFF)) |
                     ((level & 0x7) << AUDIO_I2S_MPS3_CONTROL_TX_BUFF_IRQ_WATER_LVL_OFF);
}

uint8_t audio_i2s_mps3_get_tx_buff_water_lvl(struct audio_i2s_mps3_dev_t* dev){
    struct audio_i2s_mps3_reg_map_t* p_i2s = (struct audio_i2s_mps3_reg_map_t*)dev->cfg->base;

    return (uint8_t)((p_i2s->control >> AUDIO_I2S_MPS3_CONTROL_TX_BUFF_IRQ_WATER_LVL_OFF) & 0x7);
}

void audio_i2s_mps3_set_rx_buff_water_lvl(struct audio_i2s_mps3_dev_t* dev,
                                          uint8_t level){
    struct audio_i2s_mps3_reg_map_t* p_i2s = (struct audio_i2s_mps3_reg_map_t*)dev->cfg->base;
    p_i2s->control = (p_i2s->control & ~(0x7 << AUDIO_I2S_MPS3_CONTROL_RX_BUFF_IRQ_WATER_LVL_OFF)) |
                     ((level & 0x7) << AUDIO_I2S_MPS3_CONTROL_RX_BUFF_IRQ_WATER_LVL_OFF);
}

uint8_t audio_i2s_mps3_get_rx_buff_water_lvl(struct audio_i2s_mps3_dev_t* dev){
    struct audio_i2s_mps3_reg_map_t* p_i2s = (struct audio_i2s_mps3_reg_map_t*)dev->cfg->base;

    return (uint8_t)((p_i2s->control >> AUDIO_I2S_MPS3_CONTROL_RX_BUFF_IRQ_WATER_LVL_OFF) & 0x7);
}
