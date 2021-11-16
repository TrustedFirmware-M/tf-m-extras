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

#ifndef __VAD_AN552_DEVICE_DEFINITION_H__
#define __VAD_AN552_DEVICE_DEFINITION_H__

#ifdef __cplusplus
extern "C" {
#endif

#define SYSTIMER3_ARMV8M_DEFAULT_FREQ_HZ    (32000000ul)

#include "systimer_armv8-m_drv.h"
extern struct systimer_armv8_m_dev_t SYSTIMER3_ARMV8_M_DEV_S;

#include "i2c_sbcon_drv.h"
extern struct i2c_sbcon_dev_t I2C0_SBCON_DEV_S;

#include "audio_i2s_mps3_drv.h"
extern struct audio_i2s_mps3_dev_t MPS3_I2S_DEV_S;

#ifdef __cplusplus
}
#endif

#endif  /* __VAD_AN552_DEVICE_DEFINITION_H__ */
