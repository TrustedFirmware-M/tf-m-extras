/*
 * Copyright (c) 2021-2022 Arm Limited. All rights reserved.
 *
 * Licensed under the Apache License Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing software
 * distributed under the License is distributed on an "AS IS" BASIS
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "vad_an552_device_definition.h"
#include "platform_base_address.h"
#include "timeout.h"

static const struct systimer_armv8_m_dev_cfg_t
SYSTIMER3_ARMV8_M_DEV_CFG_S = {
    .base = SYSTIMER3_ARMV8_M_BASE_S,
    .default_freq_hz = SYSTIMER3_ARMV8M_DEFAULT_FREQ_HZ
};
static struct systimer_armv8_m_dev_data_t
SYSTIMER3_ARMV8_M_DEV_DATA_S = {
    .is_initialized = false
};
struct systimer_armv8_m_dev_t SYSTIMER3_ARMV8_M_DEV_S = {
    &(SYSTIMER3_ARMV8_M_DEV_CFG_S),
    &(SYSTIMER3_ARMV8_M_DEV_DATA_S)
};

static struct i2c_sbcon_dev_cfg_t I2C0_SBCON_DEV_CFG_S = {
    .base = FPGA_SBCon_I2C_AUDIO_BASE_S,
    .default_freq_hz = 100000,
    .sleep_us = &wait_us
};
static struct i2c_sbcon_dev_data_t I2C0_SBCON_DEV_DATA_S ={
    .freq_us = 0,
    .sys_clk = 0,
    .state = 0
};
struct i2c_sbcon_dev_t I2C0_SBCON_DEV_S = {
    .cfg = &(I2C0_SBCON_DEV_CFG_S),
    .data = &(I2C0_SBCON_DEV_DATA_S)
};

static const struct audio_i2s_mps3_dev_cfg_t MPS3_I2S_DEV_CFG_S = {
    .base = FPGA_I2S_BASE_S
};
struct audio_i2s_mps3_dev_t MPS3_I2S_DEV_S = {
    &(MPS3_I2S_DEV_CFG_S),
};
