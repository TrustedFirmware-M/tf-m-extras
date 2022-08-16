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
#include "dma350_lib_unprivileged.h"

#include "example_tasks.h"
#include "pattern.h"

#define PAVED_W         64
#define PAVED_H         64
#define START_MARGIN    14
#define INNER_MARGIN_W  12
#define INNER_MARGIN_H  10

void drawTask(void *pvParameters)
{
    uint32_t to_x;
    uint32_t to_y;
    BaseType_t xStatus = pdPASS;
    enum example_tasks_queue_action_t req_action;
    enum dma350_lib_transform_t transform = DMA350_LIB_TRANSFORM_NONE;

    for(to_x = START_MARGIN; to_x + PAVED_W <= BUFFER_WIDTH; to_x += PAVED_W + INNER_MARGIN_W) {
        for(to_y = START_MARGIN; to_y + PAVED_H <= BUFFER_HEIGHT; to_y += PAVED_H + INNER_MARGIN_H) {
            dma350_draw_from_bitmap_unpriv(1, pattern,
                    &shared_clcd_buffer[to_y][to_x],
                    PAT_W, PAT_H, PAVED_W, PAVED_H, BUFFER_WIDTH,
                    DMA350_CH_TRANSIZE_16BITS,
                    transform, DMA350_LIB_EXEC_BLOCKING);
            transform++;
            if(transform > DMA350_LIB_TRANSFORM_MIRROR_TRBL) {
                transform = DMA350_LIB_TRANSFORM_NONE;
            }
        }
        /* Request Display after each completed column */
        req_action = EX_TASK_ACTION_DRAW;
        xStatus = xQueueSendToBack(xQueue, (uint32_t *)&req_action, portMAX_DELAY);
        /* Wait to be notified from the clcd Task once the image is displayed. */
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    }
    req_action = EX_TASK_ACTION_NO_MORE_DRAWING;
    xStatus = xQueueSendToBack(xQueue, (uint32_t *)&req_action, portMAX_DELAY);
    vTaskDelete(NULL);
}
