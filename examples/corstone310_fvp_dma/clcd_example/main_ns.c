/*
 * Copyright (c) 2017-2022 Arm Limited
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
#include "uart_stdout.h"
#include "print_log.h"

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "mpu_wrappers.h"

#include "example_tasks.h"

QueueHandle_t xQueue __attribute__( ( aligned( 32 ) ) ) ;
TaskHandle_t clcd_task_handle;
TaskHandle_t draw_task_handle;

/*
 * Semihosting is a mechanism that enables code running on an ARM target
 * to communicate and use the Input/Output facilities of a host computer
 * that is running a debugger.
 * There is an issue where if you use armclang at -O0 optimisation with
 * no parameters specified in the main function, the initialisation code
 * contains a breakpoint for semihosting by default. This will stop the
 * code from running before main is reached.
 * Semihosting can be disabled by defining __ARM_use_no_argv symbol
 * (or using higher optimization level).
 */
#if defined (__ARMCC_VERSION) && (__ARMCC_VERSION >= 6010050)
__asm("  .global __ARM_use_no_argv\n");
#endif

extern uint32_t tfm_ns_interface_init(void);

/* The queue is shared between the privileged and unprivileged task, so it
 * needs to be statically allocated. */
/* The queue is to be created to hold a maximum of 2 enum example_tasks_queue_action_t
variables. */
#define QUEUE_LENGTH            2
#define ITEM_SIZE               sizeof( enum example_tasks_queue_action_t )

/* The variable used to hold the queue's data structure. */
static StaticQueue_t xStaticQueue __attribute__( ( aligned( 32 ) ) ) ;

/* The array to use as the queue's storage area.  This must be at least
uxQueueLength * uxItemSize bytes. */
uint8_t ucQueueStorageArea[ QUEUE_LENGTH * ITEM_SIZE ] __attribute__( ( aligned( 32 ) ) );

int main()
{
    static StackType_t drawTaskStack[ configMINIMAL_STACK_SIZE ]
                       __attribute__( ( aligned( 32 ) ) );
    static StackType_t clcdTaskStack[ configMINIMAL_STACK_SIZE ]
                       __attribute__( ( aligned( 32 ) ) );

    stdio_init();
    vUARTLockInit();
    tfm_ns_interface_init();

    xQueue = xQueueCreateStatic(QUEUE_LENGTH, ITEM_SIZE, ucQueueStorageArea, &xStaticQueue);
    if (xQueue == NULL){
        vLoggingPrintf("Failed to create queue..");
        while(1);
    }

    /* The unprivileged task can only access the queue, 1st DMA channel, and the display+pattern buffer. */
    TaskParameters_t drawTaskParameters =
    {
        .pvTaskCode     = drawTask,
        .pcName         = "drawTask",
        .usStackDepth   = configMINIMAL_STACK_SIZE,
        .pvParameters   = NULL,
        .uxPriority     = tskIDLE_PRIORITY,
        .puxStackBuffer = drawTaskStack,
        .xRegions       =
        {
            { &xQueue, sizeof(&xQueue), tskMPU_REGION_READ_ONLY | tskMPU_REGION_EXECUTE_NEVER },
            { DMA350_DMA0_CH1_DEV_NS.cfg.ch_base, 0x100,
                        tskMPU_REGION_READ_WRITE | tskMPU_REGION_EXECUTE_NEVER },
            { &shared_clcd_buffer, sizeof(shared_clcd_buffer), tskMPU_REGION_READ_WRITE | tskMPU_REGION_EXECUTE_NEVER },
        }
    };
    TaskParameters_t clcdTaskParameters =
    {
        .pvTaskCode     = clcdTask,
        .pcName         = "clcdTask",
        .usStackDepth   = configMINIMAL_STACK_SIZE,
        .pvParameters   = NULL,
        .uxPriority     = tskIDLE_PRIORITY | portPRIVILEGE_BIT,
        .puxStackBuffer = clcdTaskStack,
        .xRegions       =
        {
            { 0, 0, 0 },
        }
    };

    /* Create tasks */
    xTaskCreateRestricted( &( drawTaskParameters ), &draw_task_handle );
    xTaskCreateRestricted( &( clcdTaskParameters ), &clcd_task_handle );

    vLoggingPrintf("Starting FreeRTOS scheduler");

    /* Start the scheduler itself. */
    vTaskStartScheduler();

    while (1)
    {
    }
}
