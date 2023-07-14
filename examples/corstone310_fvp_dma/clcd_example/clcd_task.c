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
#include "print_log.h"

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "dma350_lib.h"
#include "clcd_mps3_lib.h"

#include "clcd_dma_wrapper.h"
#include "example_tasks.h"

#define CMD_BUFFER_LEN 40

void clcdTask(void *pvParameters)
{
    uint32_t cmd_buffer[CMD_BUFFER_LEN];
    uint32_t* first_command;
    enum example_tasks_queue_action_t req_action = EX_TASK_ACTION_NO_MORE_DRAWING;
    BaseType_t xStatus = pdPASS;

    vLoggingPrintf("Starting clcdTask");

    clcd_mps3_init(&MPS3_CLCD_DEV_NS);

    generate_dma_cmdlinks_for_display(&shared_clcd_buffer[0][0], &MPS3_CLCD_DEV_NS,
                                    cmd_buffer, &cmd_buffer[CMD_BUFFER_LEN],
                                    &first_command);

    while(1){
        xStatus = xQueueReceive(xQueue, (uint32_t *)&req_action, portMAX_DELAY);
        if (xStatus == pdPASS){
            vLoggingPrintf("Received request from draw task: %d", req_action);
            if(req_action == EX_TASK_ACTION_DRAW) {
                display_image_with_dma(first_command,
                                    &DMA350_DMA0_CH1_DEV_NS,
                                    &MPS3_CLCD_DEV_NS);
                xTaskNotifyGive( draw_task_handle );
            } else if(req_action == EX_TASK_ACTION_NO_MORE_DRAWING) {
                vLoggingPrintf("No more drawing.");
                break;
            } else {
                vLoggingPrintf("Unexpected request!");
            }
        } else {
            vLoggingPrintf("Error in queue reception.");
        }
    }
    vLoggingPrintf("Delete clcd Task");
    vTaskDelete(NULL);
}
