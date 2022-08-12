/*
 * Copyright (c) 2022 Arm Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "platform_base_address.h"
#include "dma350_drv.h"
#include "dma350_ch_drv.h"
#include "dma350_regdef.h"
#include "dma350_checker_layer.h"

/* DMA Channel Device structure definition */
struct dma350_ch_dev_t DMA350_DMA0_CH1_DEV_NS = {
    .cfg = {.ch_base = (DMACH_TypeDef *)(DMA_350_BASE_NS + 0x1100UL),
            .channel = 1},
    .data = {0}};
struct dma350_ch_dev_t* const DMA350_DMA0_NS_CHANNELS[] = {
    NULL,
    &DMA350_DMA0_CH1_DEV_NS
};

struct dma350_checker_channels_t const DMA350_CHECKER_CHANNELS = {
    .channels = DMA350_DMA0_NS_CHANNELS,
    .number_of_channels = sizeof(DMA350_DMA0_NS_CHANNELS) /
                          sizeof(DMA350_DMA0_NS_CHANNELS[0])
};
