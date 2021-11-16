/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

/**
 * \file audio_codec_mps3.h
 *
 * \brief CS42L52 Audio Codec configuration.
 * The control port operates using an I2C interface.
 */

#ifndef __AUDIO_CODEC_MPS3_H__
#define __AUDIO_CODEC_MPS3_H__

#include <stdint.h>
#include "i2c_sbcon_drv.h"
#include "audio_i2s_mps3_drv.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief CS42L52 Audio Codec error enumeration types
 */
enum audio_codec_mps3_error_t {
    AUDIO_CODEC_MPS3_ERR_NONE = 0,      /*!< No error */
};

/**
 * \brief Initializes Audio Codec
 *
 * \param[in] i2c_sbcon_dev I2C device struct \ref i2c_sbcon_dev
 * \param[in] audio_i2s_mps3_dev I2S device struct \ref audio_i2s_mps3_dev_t
 *
 * \return Returns error code as specified in \ref audio_codec_mps3_error_t
 */
enum audio_codec_mps3_error_t audio_codec_mps3_init(
                            struct i2c_sbcon_dev_t *i2c_sbcon_dev,
                            struct audio_i2s_mps3_dev_t *audio_i2s_mps3_dev);

#ifdef __cplusplus
}
#endif
#endif /* __AUDIO_CODEC_MPS3_H__ */
