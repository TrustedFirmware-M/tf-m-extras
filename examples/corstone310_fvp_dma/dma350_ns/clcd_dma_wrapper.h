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

#include <stdint.h>
#include "dma350_ch_drv.h"
#include "clcd_mps3_drv.h"

/**
 * @brief Display a fixed size image on the LCD.
 *
 * @param first_command[in]  Pointer to the first command.
 * @param ch_dev[in]         DMA350 channel device.
 * @param clcd_dev[in]       CLCD device.
 */
void display_image_with_dma(uint32_t* first_command,
                            struct dma350_ch_dev_t* ch_dev,
                            struct clcd_mps3_dev_t* clcd_dev);

/**
 * @brief Generate command links to display a fixed size image on the LCD.
 *
 * @param picture_bitmap[in]    Image buffer to be displayed.
 * @param clcd_dev[in]          CLCD device.
 * @param cmd_buffer[in]        Buffer to hold generated command links.
 * @param cmd_buffer_limit[in]  Buffer limit.
 * @param first_command[out]    Address of first command.
 */
void generate_dma_cmdlinks_for_display(const uint16_t* picture_bitmap,
                                       struct clcd_mps3_dev_t* clcd_dev,
                                       uint32_t* cmd_buffer,
                                       uint32_t* cmd_buffer_limit,
                                       uint32_t** first_command);
