/*
 * Copyright (c) 2021 Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "FreeRTOS.h"
#include "task.h"
#include "FreeRTOS_IP.h"
#include "FreeRTOS_Sockets.h"
#include "NetworkBufferManagement.h"
#include "NetworkInterface.h"
#include "FreeRTOS_IP_Private.h"
#include "semphr.h"

#include "cmsis.h"
#include "platform_eth_dev.h"
#include "smsc9220_eth_drv.h"

static TaskHandle_t xReceiveTaskHandle = NULL;
static SemaphoreHandle_t xTXSemaphore;

static void smsc9220_Receive_task(void *pvParameters);

static void wait_ms(int sleep_ms)
{
    vTaskDelay(pdMS_TO_TICKS(sleep_ms));
}

BaseType_t xNetworkInterfaceInitialise(void)
{
    enum smsc9220_error_t ret = SMSC9220_ERROR_NONE;
    char MACaddr[ipMAC_ADDRESS_LENGTH_BYTES] = {0};

    ret = smsc9220_init(&ETH_DEV, &wait_ms);

    if (ret != SMSC9220_ERROR_NONE) {
        FreeRTOS_debug_printf(("Error in SMSC 9220 Ethernet init.\n"));
        return pdFALSE;
    } else {
        FreeRTOS_debug_printf(("SMSC 9220 Ethernet driver initialized.\n"));
    }

    /* Init FIFO level interrupts: use Rx status level irq to trigger
     * interrupts for any non-processed packets, while Tx is not irq driven */
    smsc9220_set_fifo_level_irq(&ETH_DEV,
                                SMSC9220_FIFO_LEVEL_IRQ_RX_STATUS_POS,
                                SMSC9220_FIFO_LEVEL_IRQ_LEVEL_MIN);

    smsc9220_read_mac_address(&ETH_DEV, MACaddr);
    FreeRTOS_UpdateMACAddress((const uint8_t *)MACaddr);

    xTXSemaphore = xSemaphoreCreateMutex();

    /* Create receiver task */
    xTaskCreate(smsc9220_Receive_task, "smsc9220 receive", 4096, NULL,
                configMAX_PRIORITIES-2, &xReceiveTaskHandle);

    return pdTRUE;
}

BaseType_t xNetworkInterfaceOutput(
                                NetworkBufferDescriptor_t * const pxDescriptor,
                                BaseType_t xReleaseAfterSend)
{
    enum smsc9220_error_t ret;
    xSemaphoreTake(xTXSemaphore, portMAX_DELAY);
    ret = smsc9220_send_by_chunks(&ETH_DEV,
                                  (uint32_t)pxDescriptor->xDataLength, true,
                                  (char*)pxDescriptor->pucEthernetBuffer,
                                  (uint32_t)pxDescriptor->xDataLength);
    xSemaphoreGive(xTXSemaphore);

    if (ret != SMSC9220_ERROR_NONE) {
        FreeRTOS_debug_printf(("error in send_by_chunks\r\n"));
    }

    /* Call the standard trace macro to log the send event. */
    iptraceNETWORK_INTERFACE_TRANSMIT();

    if (xReleaseAfterSend == pdTRUE) {
        vReleaseNetworkBufferAndDescriptor(pxDescriptor);
    }

    return pdTRUE;
}

void ETHERNET_Handler(void)
{
    BaseType_t taskWoken = pdFALSE;
    if (smsc9220_get_interrupt(&ETH_DEV,
                                SMSC9220_INTERRUPT_RX_STATUS_FIFO_LEVEL)) {

        smsc9220_disable_interrupt(&ETH_DEV,
                                   SMSC9220_INTERRUPT_RX_STATUS_FIFO_LEVEL);
        smsc9220_clear_interrupt(&ETH_DEV,
                                 SMSC9220_INTERRUPT_RX_STATUS_FIFO_LEVEL);
        NVIC_ClearPendingIRQ(ETHERNET_IRQn);

        vTaskNotifyGiveFromISR(xReceiveTaskHandle, &taskWoken);
        portYIELD_FROM_ISR(taskWoken);
    }
}

static void smsc9220_Receive_task(void *pvParameters)
{
    FreeRTOS_debug_printf(("smsc9220 ethernet receive task created\r\n"));
    uint32_t message_length = 0;
    NetworkBufferDescriptor_t *pxBufferDescriptor;
    IPStackEvent_t xRxEvent;

    NVIC_SetPriority(ETHERNET_IRQn, configMAC_INTERRUPT_PRIORITY);
    NVIC_EnableIRQ(ETHERNET_IRQn);

    while (1) {
        smsc9220_enable_interrupt(&ETH_DEV,
                                  SMSC9220_INTERRUPT_RX_STATUS_FIFO_LEVEL);
        /* Sleep thread until notified from Ethernet ISR */
        ulTaskNotifyTake(pdFALSE, portMAX_DELAY);

        /* Peak transfer size */
        message_length = smsc9220_peek_next_packet_size(&ETH_DEV);
        if (message_length == 0) {
            /* There are no packets to read */
            continue;
        }

        /* Allocate a network buffer descriptor that points to a buffer
        large enough to hold the received frame.  As this is the simple
        rather than efficient example the received data will just be copied
        into this buffer. */
        pxBufferDescriptor =
                        pxGetNetworkBufferWithDescriptor(message_length, 0);

        if(pxBufferDescriptor != NULL) {
            if( SMSC9220_ERROR_NONE != smsc9220_get_received_packet(&ETH_DEV,
                                 (char *)pxBufferDescriptor->pucEthernetBuffer,
                                 message_length)) {
                /* Packet size mismatch, try again at next interrupt */
                continue;
            }

            pxBufferDescriptor->xDataLength = message_length;

            if(eConsiderFrameForProcessing(
               pxBufferDescriptor->pucEthernetBuffer) != eProcessBuffer) {
                vReleaseNetworkBufferAndDescriptor(pxBufferDescriptor);
                continue;
            }

            xRxEvent.eEventType = eNetworkRxEvent;

            xRxEvent.pvData = (void *) pxBufferDescriptor;

            /* Send the data to the TCP/IP stack. */
            if( xSendEventStructToIPTask(&xRxEvent, 0) == pdFALSE )
            {
                /* Buffer send failed */
                vReleaseNetworkBufferAndDescriptor(pxBufferDescriptor);
                iptraceETHERNET_RX_EVENT_LOST();
            }
            else
            {
                /* Send successful */
                iptraceNETWORK_INTERFACE_RECEIVE();
            }
        }
        else
        {
            /* Event was lost */
            iptraceETHERNET_RX_EVENT_LOST();
        }

    }
}
