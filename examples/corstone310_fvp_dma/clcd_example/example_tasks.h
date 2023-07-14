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

#include "stdint.h"

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"

#include "clcd_mps3_drv.h"
#include "dma350_ch_drv.h"

#define BUFFER_WIDTH   320
#define BUFFER_HEIGHT  240

extern uint16_t shared_clcd_buffer[BUFFER_HEIGHT][BUFFER_WIDTH];
extern struct clcd_mps3_dev_t MPS3_CLCD_DEV_NS;
extern struct dma350_ch_dev_t DMA350_DMA0_CH1_DEV_NS;

/* Actions the draw task could request from the clcd task via a shared queue */
enum example_tasks_queue_action_t {
    EX_TASK_ACTION_DRAW = 0,
    EX_TASK_ACTION_NO_MORE_DRAWING
};

extern QueueHandle_t xQueue __attribute__( ( aligned( 32 ) ) ) ;
extern TaskHandle_t draw_task_handle;

/**
 * @brief Sequentially draws 64x64 images into a display buffer, using the DMA,
 *        and sends display request to the privileged clcd task after each draw.
 *
 * @param pvParameters[in] Parameters as passed during task creation.
 */
void drawTask( void * pvParameters );

/**
 * @brief Displays the display buffer on the CLCD screen, when triggered from
 *        the unprivileged task.
 *
 * @param pvParameters[in] Parameters as passed during task creation.
 */
void clcdTask( void * pvParameters );
