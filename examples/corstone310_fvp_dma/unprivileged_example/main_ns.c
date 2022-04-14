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


#include "stdio.h"
#include "stdbool.h"
#include "string.h"
#include "uart_stdout.h"
#include "print_log.h"

#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "mpu_wrappers.h"
#include "dma350_drv.h"
#include "device_definition.h"
#include "dma350_lib_unprivileged.h"

extern uint32_t tfm_ns_interface_init(void);

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

/*
 * With current clib settings there is no support for errno in case of Armclang
 * but OTA sources require it.
 */
#if defined (__ARMCC_VERSION)
int errno;
#endif

/* The queue is shared between the privileged and unprivileged task, so it
 * needs to be statically allocated. */
/* The queue is to be created to hold a maximum of 10 uint32_t
variables. */
#define QUEUE_LENGTH            10
#define ITEM_SIZE               sizeof( uint32_t )
#define STRING_TO_MOVE_LENGTH   13
/* The variable used to hold the queue's data structure. */
static StaticQueue_t xStaticQueue __attribute__( ( aligned( 32 ) ) ) ;

/* The array to use as the queue's storage area.  This must be at least
uxQueueLength * uxItemSize bytes. */
uint8_t ucQueueStorageArea[ QUEUE_LENGTH * ITEM_SIZE ] __attribute__( ( aligned( 32 ) ) );
QueueHandle_t xQueue __attribute__( ( aligned( 32 ) ) ) ;
char dma350_test_memory_dst[32] __attribute__( ( aligned( 32 ) ) );

extern struct dma350_ch_dev_t DMA350_DMA0_CH1_DEV_NS;
/**
 * @brief Starts an ADA DMA transaction, then sends the error result
 *        code to the priv task.
 *
 * @param pvParameters[in] Parameters as passed during task creation.
 */
static void unprivTask( void * pvParameters );

/**
 * @brief Waits until the unpriv task finishes the DMA transaction
 *        and prints the result code, and destination buffer content.
 *
 * @param pvParameters[in] Parameters as passed during task creation.
 */
static void privTask( void * pvParameters );

static void unprivTask(void *pvParameters)
{
    BaseType_t xStatus = pdPASS;
    char dma350_test_memory_src[STRING_TO_MOVE_LENGTH] = "NS Copy Test";
    enum dma350_lib_error_t dma_config_ret_val = DMA350_LIB_ERR_INVALID_CONFIG_TYPE;

    dma_config_ret_val = dma350_memmove_unpriv(1,
                                               (void *)dma350_test_memory_src,
                                               (void *)dma350_test_memory_dst,
                                               STRING_TO_MOVE_LENGTH,
                                               DMA350_LIB_EXEC_BLOCKING);

    xStatus = xQueueSendToBack(xQueue, (uint32_t *)&dma_config_ret_val, portMAX_DELAY);

    while(1)
    {
        vTaskDelay(10);
    }
}

static void privTask(void *pvParameters)
{
    enum dma350_lib_error_t dma_config_ret_val = 0;
    BaseType_t xStatus = pdPASS;

    vLoggingPrintf("Starting privTask");

    while(1){
        xStatus = xQueueReceive(xQueue, (uint32_t *)&dma_config_ret_val, portMAX_DELAY);
        if (xStatus == pdPASS){
            vLoggingPrintf("Received DMA return status from unprivileged task: %d",
                            dma_config_ret_val);
            vLoggingPrintf("Buffer after DMA transaction: %s", dma350_test_memory_dst);
        } else {
            vLoggingPrintf("Error in queue reception.");
        }
    }

    vTaskDelete(NULL);
}

int main()
{
    static StackType_t unprivTaskStack[ configMINIMAL_STACK_SIZE ]
                       __attribute__( ( aligned( 32 ) ) );
    static StackType_t privTaskStack[ configMINIMAL_STACK_SIZE ]
                       __attribute__( ( aligned( 32 ) ) );

    xQueue = xQueueCreateStatic(QUEUE_LENGTH, ITEM_SIZE, ucQueueStorageArea, &xStaticQueue);
    if (xQueue == NULL){
        vLoggingPrintf("Failed to create queue..");
        while(1);
    }

    /* The unprivileged task can only access the 1st DMA channel and the test memory. */
    TaskParameters_t unprivTaskParameters =
    {
        .pvTaskCode     = unprivTask,
        .pcName         = "unprivTask",
        .usStackDepth   = configMINIMAL_STACK_SIZE,
        .pvParameters   = NULL,
        .uxPriority     = tskIDLE_PRIORITY,
        .puxStackBuffer = unprivTaskStack,
        .xRegions       =
        {
            { &xQueue, sizeof(&xQueue), tskMPU_REGION_READ_ONLY | tskMPU_REGION_EXECUTE_NEVER },
            { DMA350_DMA0_CH1_DEV_NS.cfg.ch_base, 0x100,
                        tskMPU_REGION_READ_WRITE | tskMPU_REGION_EXECUTE_NEVER },
            { dma350_test_memory_dst, 32,
                        tskMPU_REGION_READ_WRITE | tskMPU_REGION_EXECUTE_NEVER },
        }
    };
    TaskParameters_t privTaskParameters =
    {
        .pvTaskCode     = privTask,
        .pcName         = "privTask",
        .usStackDepth   = configMINIMAL_STACK_SIZE,
        .pvParameters   = NULL,
        .uxPriority     = tskIDLE_PRIORITY | portPRIVILEGE_BIT,
        .puxStackBuffer = privTaskStack,
        .xRegions       =
        {
            { 0, 0, 0 },
        }
    };

    stdio_init();
    vUARTLockInit();
    tfm_ns_interface_init();

    /* Create tasks */
    xTaskCreateRestricted( &( unprivTaskParameters ), NULL );
    xTaskCreateRestricted( &( privTaskParameters ), NULL );

    vLoggingPrintf("Starting FreeRTOS scheduler");

    /* Start the scheduler itself. */
    vTaskStartScheduler();

    while (1)
    {
    }
}
