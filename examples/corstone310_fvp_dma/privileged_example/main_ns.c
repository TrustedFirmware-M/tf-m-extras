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
#include "dma350_drv.h"
#include "clcd_mps3_drv.h"
#include "clcd_mps3_lib.h"
#include "clcd_mps3_reg_map.h"

extern uint32_t tfm_ns_interface_init(void);
extern const unsigned short picture_bitmap[];
extern struct clcd_mps3_dev_t MPS3_CLCD_DEV_NS;
extern struct dma350_ch_dev_t DMA350_DMA0_CH1_DEV_NS;
extern struct clcd_mps3_dev_t MPS3_CLCD_DEV_NS;

extern void display_image_with_dma(const unsigned short picture_bitmap[],
                                   struct dma350_ch_dev_t* ch_dev,
                                   struct clcd_mps3_dev_t* clcd_dev);


TaskHandle_t clcd_task_handle;

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

/**
 * @brief Init the LCD and display an image with DMA350 on the LCD.
 *
 * @param pvParameters[in] Parameters as passed during task creation.
 */
static void clcdTask(void *pvParameters)
{
    vLoggingPrintf("Starting clcdTask");

    clcd_mps3_init(&MPS3_CLCD_DEV_NS);
    clcd_mps3_lib_set_window(&MPS3_CLCD_DEV_NS, 0, 0, 320, 240);

    display_image_with_dma(picture_bitmap, &DMA350_DMA0_CH1_DEV_NS, &MPS3_CLCD_DEV_NS);

    vTaskDelete(NULL);
}

int main()
{
    stdio_init();
    vUARTLockInit();
    tfm_ns_interface_init();

    xTaskCreate( clcdTask,
                "clcdTask",
                configMINIMAL_STACK_SIZE,
                NULL,
                configMAX_PRIORITIES,
                &clcd_task_handle );

    vLoggingPrintf("Starting FreeRTOS scheduler");


    /* Start the scheduler itself. */
    vTaskStartScheduler();

    while (1)
    {
    }
}
