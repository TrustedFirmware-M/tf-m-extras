/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

/**
 * \file audio_i2s_mps3_drv.h
 *
 * \brief Driver for Audio I2S
 *
 * The I2S interface supports transfer of digital audio to and
 * from the Audio CODEC
 *
 * Main features:
 *   - Clear/Set Control Register bits to enable or disable buffer or interrupt
 *     and to reset Audio codec or FIFO
 *   - Check status of receive and transmit buffer
 *   - Get receive buffer data
 *   - Set transmit buffer data
 *   - Get Control, Status, Error register value
 *   - Write/Read sample
 */

#ifndef __AUDIO_I2S_MPS3_DRV_H__
#define __AUDIO_I2S_MPS3_DRV_H__

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Audio I2S device configuration structure
 */
struct audio_i2s_mps3_dev_cfg_t{
    const uint32_t base;
    /*!< Audio I2S device base address */
};

/**
 * \brief Audio I2S device structure
 */
struct audio_i2s_mps3_dev_t {
    const struct audio_i2s_mps3_dev_cfg_t* const cfg;
    /*!< Audio I2S configuration structure */
};

/**
 * \brief I2S audio sample structure
 */
struct audio_i2s_mps3_sample_t{
    uint16_t left_channel;
    uint16_t right_channel;
};

/**
 * \brief Audio I2S error enumeration types
 */
enum audio_i2s_mps3_error_t{
    AUDIO_I2S_MPS3_ERR_NONE = 0,      /*!< No error */
    AUDIO_I2S_MPS3_ERR_INVALID_ARG,   /*!< Error invalid input argument */
};

/**
 * \brief Reset Audio codec
 *
 * \param[in] dev Audio I2S device struct \ref audio_i2s_mps3_dev_t
 */
void audio_i2s_mps3_set_codec_reset(struct audio_i2s_mps3_dev_t* dev);

/**
 * \brief Reset FIFO
 *
 * \param[in] dev Audio I2S device struct \ref audio_i2s_mps3_dev_t
 */
void audio_i2s_mps3_set_fifo_reset(struct audio_i2s_mps3_dev_t* dev);

/**
 * \brief Clear Audio codec reset
 *
 * \param[in] dev Audio I2S device struct \ref audio_i2s_mps3_dev_t
 */
void audio_i2s_mps3_clear_codec_reset(struct audio_i2s_mps3_dev_t* dev);

/**
 * \brief Clear FIFO reset
 *
 * \param[in] dev Audio I2S device struct \ref audio_i2s_mps3_dev_t
 */
void audio_i2s_mps3_clear_fifo_reset(struct audio_i2s_mps3_dev_t* dev);

/**
 * \brief Checks if Receive Buffer is empty
 *
 * \param[in] dev Audio I2S device struct \ref audio_i2s_mps3_dev_t
 *
 * \return True if it is empty, False otherwise
 */
bool audio_i2s_mps3_is_rx_buffer_empty(struct audio_i2s_mps3_dev_t* dev);

/**
 * \brief Checks if Receive Buffer is full
 *
 * \param[in] dev Audio I2S device struct \ref audio_i2s_mps3_dev_t
 *
 * \return True if it is full, False otherwise
 */
bool audio_i2s_mps3_is_rx_buffer_full(struct audio_i2s_mps3_dev_t* dev);

/**
 * \brief Checks if Transmit Buffer is empty
 *
 * \param[in] dev Audio I2S device struct \ref audio_i2s_mps3_dev_t
 *
 * \return True if it is empty, False otherwise
 */
bool audio_i2s_mps3_is_tx_buffer_empty(struct audio_i2s_mps3_dev_t* dev);

/**
 * \brief Checks if Transmit Buffer is full
 *
 * \param[in] dev Audio I2S device struct \ref audio_i2s_mps3_dev_t
 *
 * \return True if it is full, False otherwise
 */
bool audio_i2s_mps3_is_tx_buffer_full(struct audio_i2s_mps3_dev_t* dev);

/**
 * \brief Sets clock divider value
 *
 * \param[in] dev   Audio I2S device struct \ref audio_i2s_mps3_dev_t
 * \param[in] lrdiv divide value
 *
 * \return Returns error code as specified in \ref audio_i2s_mps3_error_t
 */
enum audio_i2s_mps3_error_t audio_i2s_mps3_speed_config(struct audio_i2s_mps3_dev_t* dev, uint16_t lrdiv);

/**
 * \brief Get Receive Buffer FIFO Data Register
 *
 * \param[in] dev Audio I2S device struct \ref audio_i2s_mps3_dev_t
 *
 * \return Returns register value
 */
uint32_t audio_i2s_mps3_get_rxbuf(struct audio_i2s_mps3_dev_t* dev);

/**
 * \brief Set Transmit Buffer Fifo Data Register
 *
 * \param[in] dev            Audio I2S device struct \ref audio_i2s_mps3_dev_t
 * \param[in] left_channel   audio left channel value
 * \param[in] right_channel  audio right channel value
 */
void audio_i2s_mps3_set_txbuf(struct audio_i2s_mps3_dev_t* dev, uint16_t left_channel,
                    uint16_t right_channel);

/**
 * \brief Enable Receive Buffer
 *
 * \param[in] dev Audio I2S device struct \ref audio_i2s_mps3_dev_t
 */
void audio_i2s_mps3_enable_rxbuf(struct audio_i2s_mps3_dev_t* dev);

/**
 * \brief Enable Receive Interrupt
 *
 * \param[in] dev Audio I2S device struct \ref audio_i2s_mps3_dev_t
 */
void audio_i2s_mps3_enable_rxinterrupt(struct audio_i2s_mps3_dev_t* dev);

/**
 * \brief Enable Transmit Buffer
 *
 * \param[in] dev Audio I2S device struct \ref audio_i2s_mps3_dev_t
 */
void audio_i2s_mps3_enable_txbuf(struct audio_i2s_mps3_dev_t* dev);

/**
 * \brief Enable Transmit Interrupt
 *
 * \param[in] dev Audio I2S device struct \ref audio_i2s_mps3_dev_t
 */
void audio_i2s_mps3_enable_txinterrupt(struct audio_i2s_mps3_dev_t* dev);

/**
 * \brief Disable Receive Buffer
 *
 * \param[in] dev Audio I2S device struct \ref audio_i2s_mps3_dev_t
 */
void audio_i2s_mps3_disable_rxbuf(struct audio_i2s_mps3_dev_t* dev);

/**
 * \brief Disable Receive Interrupt
 *
 * \param[in] dev Audio I2S device struct \ref audio_i2s_mps3_dev_t
 */
void audio_i2s_mps3_disable_rxinterrupt(struct audio_i2s_mps3_dev_t* dev);

/**
 * \brief Disable Transmit Buffer
 *
 * \param[in] dev Audio I2S device struct \ref audio_i2s_mps3_dev_t
 */
void audio_i2s_mps3_disable_txbuf(struct audio_i2s_mps3_dev_t* dev);

/**
 * \brief Disable Transmit Interrupt
 *
 * \param[in] dev Audio I2S device struct \ref audio_i2s_mps3_dev_t
 */
void audio_i2s_mps3_disable_txinterrupt(struct audio_i2s_mps3_dev_t* dev);

/**
 * \brief Get Control Register
 *
 * \param[in] dev Audio I2S device struct \ref audio_i2s_mps3_dev_t
 *
 * \return Returns register value
 */
uint32_t audio_i2s_mps3_get_control(struct audio_i2s_mps3_dev_t* dev);

/**
 * \brief Get Status register
 *
 * \param[in] dev Audio I2S device struct \ref audio_i2s_mps3_dev_t
 *
 * \return Returns register value
 */
uint32_t audio_i2s_mps3_get_status(struct audio_i2s_mps3_dev_t* dev);

/**
 * \brief Get Error Status Register
 *
 * \param[in] dev Audio I2S device struct \ref audio_i2s_mps3_dev_t
 *
 * \return Returns register value
 */
uint32_t audio_i2s_mps3_get_error(struct audio_i2s_mps3_dev_t* dev);

/**
 * \brief Reads audio sample from Receive Buffer Register
 *
 * \param[in] dev Audio I2S device struct \ref audio_i2s_mps3_dev_t
 *
 * \returns Returns an audio_i2s_mps3_sample_t structure
 */
struct audio_i2s_mps3_sample_t read_sample(struct audio_i2s_mps3_dev_t* dev);

/**
 * \brief Writes audio sample to Transmit Buffer Register
 *  *
 * \param[in] dev      Audio I2S device struct \ref audio_i2s_mps3_dev_t
 * \param[in] sample   Value of an audio sample
 */
void write_sample(struct audio_i2s_mps3_dev_t* dev,
                  struct audio_i2s_mps3_sample_t sample);

/**
 * \brief Set Tx Buffer Interrupt Water Level
 *
 * \param[in] dev    Audio I2S device struct \ref audio_i2s_mps3_dev_t
 * \param[in] level  Water level to be set (0-7)
 */
void audio_i2s_mps3_set_tx_buff_water_lvl(struct audio_i2s_mps3_dev_t* dev,
                                          uint8_t level);

/**
 * \brief Get Tx Buffer Interrupt Water Level
 *
 * \param[in] dev    Audio I2S device struct \ref audio_i2s_mps3_dev_t
 *
 * \returns Returns Tx Buffer Interrupt Water Level
 */
uint8_t audio_i2s_mps3_get_tx_buff_water_lvl(struct audio_i2s_mps3_dev_t* dev);

/**
 * \brief Set Rx Buffer Interrupt Water Level
 *
 * \param[in] dev    Audio I2S device struct \ref audio_i2s_mps3_dev_t
 * \param[in] level  Water level to be set (0-7)
 */
void audio_i2s_mps3_set_rx_buff_water_lvl(struct audio_i2s_mps3_dev_t* dev,
                                          uint8_t level);

/**
 * \brief Get Rx Buffer Interrupt Water Level
 *
 * \param[in] dev    Audio I2S device struct \ref audio_i2s_mps3_dev_t
 *
 * \returns Returns Rx Buffer Interrupt Water Level
 */
uint8_t audio_i2s_mps3_get_rx_buff_water_lvl(struct audio_i2s_mps3_dev_t* dev);

#ifdef __cplusplus
}
#endif
#endif /* __AUDIO_I2S_MPS3_DRV_H__ */
