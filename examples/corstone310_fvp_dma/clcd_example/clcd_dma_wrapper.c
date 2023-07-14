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

#include "dma350_drv.h"
#include "dma350_ch_drv.h"
#include "clcd_mps3_drv.h"
#include "clcd_mps3_lib.h"
#include "clcd_mps3_reg_map.h"
#include "FreeRTOS.h"
#include "task.h"
#include "print_log.h"
#include "platform_irq.h"
#include "cmsis.h"
#include "clcd_dma_wrapper.h"

#define LCD_WIDTH   320
#define LCD_HEIGHT  240

static struct dma350_ch_dev_t* clcd_dma_ch_dev;
static TaskHandle_t clcd_task_notify_handle;

void dma_ch_irq_handler()
{
    if(dma350_ch_is_intr_set(clcd_dma_ch_dev, DMA350_CH_INTREN_DONE)) {
        /* All transactions finished */
        dma350_ch_clear_stat(clcd_dma_ch_dev, DMA350_CH_STAT_DONE);
        vTaskNotifyGiveFromISR( clcd_task_notify_handle, NULL );
    } else if (dma350_ch_is_intr_set(clcd_dma_ch_dev, DMA350_CH_INTREN_DESTRIGINWAIT)) {
        /* In the FVP CLCD processes the input very fast, no need to check CLCD status. */
        dma350_ch_cmd(clcd_dma_ch_dev, DMA350_CH_CMD_DESSWTRIGINREQ_BLOCK);
    } else {
        vLoggingPrintf("Error, unexpected DMA interrupt!");
        while(1);
    }
}

void display_image_with_dma(uint32_t* first_command,
                            struct dma350_ch_dev_t* ch_dev,
                            struct clcd_mps3_dev_t* clcd_dev)
{
    dma350_ch_init(ch_dev);

    clcd_dma_ch_dev = ch_dev;
    clcd_task_notify_handle = xTaskGetCurrentTaskHandle();

    /* Enable the interrupts and set the handler function */
    NVIC_SetVector(DMA_CHANNEL_0_IRQn + ch_dev->cfg.channel, (uint32_t) dma_ch_irq_handler);
    NVIC_EnableIRQ(DMA_CHANNEL_0_IRQn + ch_dev->cfg.channel);

    /* Setup an arbitrary zero-length command to start the command link */
    dma350_ch_set_xsize32(ch_dev, 0, 0);
    dma350_ch_set_ysize16(ch_dev, 0, 0);
    dma350_ch_set_xtype(ch_dev, DMA350_CH_XTYPE_CONTINUE);
    dma350_ch_set_ytype(ch_dev, DMA350_CH_YTYPE_DISABLE);

    /* Set the address of the first command */
    dma350_ch_enable_linkaddr(ch_dev);
    dma350_ch_set_linkaddr32(ch_dev, (uint32_t)first_command);
    dma350_ch_disable_intr(ch_dev, DMA350_CH_INTREN_DONE);

    clcd_mps3_lib_set_window(clcd_dev, 0, 0, LCD_WIDTH, LCD_HEIGHT);

    /* Signal to CLCD peripheral that data will be sent */
    clcd_mps3_clear_cs(clcd_dev);
    clcd_mps3_write_command(clcd_dev, 0x22);
    clcd_mps3_set_cs(clcd_dev);

    clcd_mps3_clear_cs(clcd_dev);

    vLoggingPrintf("Starting the DMA transactions");
    dma350_ch_cmd(ch_dev, DMA350_CH_CMD_ENABLECMD);

    /* Wait to be notified from the DMA channel IRQ once the image is displayed. */
    ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    vLoggingPrintf("Image displayed successfully!");

    NVIC_DisableIRQ(DMA_CHANNEL_0_IRQn + ch_dev->cfg.channel);

    /* Signal to CLCD peripheral that data transfer has ended */
    clcd_mps3_set_cs(clcd_dev);
}

void generate_dma_cmdlinks_for_display(const uint16_t* picture_bitmap,
                                       struct clcd_mps3_dev_t* clcd_dev,
                                       uint32_t* cmd_buffer,
                                       uint32_t* cmd_buffer_limit,
                                       uint32_t** first_command)
{
    /*
     * The image is diplayed using DMA350 command links to offload work from
     * the CPU. It requires 4 commands to tansfer the image data, as 2D
     * featuers are used, and all data sizes cannot fit into y register
     * of the DMA350. (Y size is limited to 16 bits.)
     * The reason for using 2D features is to change the endianness of the data
     * on the fly, as CLCD requires different endianness.
     */

    struct clcd_mps3_reg_map_t* p_clcd =
        (struct clcd_mps3_reg_map_t*) clcd_dev->cfg->base;
    uint8_t *bitmap8_ptr = (uint8_t*) picture_bitmap;
    struct dma350_cmdlink_gencfg_t cmdlink1_cfg, cmdlink2_cfg, cmdlink3_cfg,
                                   cmdlink4_cfg, cmdlink_cleanup_cfg;

    /* Quarter size in pixels */
    #define QUARTER_SIZE  (LCD_WIDTH*LCD_HEIGHT/4)
    /* Generated command link command addresses */
    uint32_t *cmd1, *cmd2, *cmd3, *cmd4, *cmd_cleanup, *check;

    /* Setup cmdlinks */

    vLoggingPrintf("Starting the DMA commandlink setup");
    /* Setup CMD 1 */
    /* Copying first quarter */
    dma350_cmdlink_init(&cmdlink1_cfg);
    /* Clear DMA registers upon loading this command */
    dma350_cmdlink_set_regclear(&cmdlink1_cfg);
    /* Set the privilege and security attributes of the transactions */
    dma350_cmdlink_set_src_trans_nonsecure(&cmdlink1_cfg);
    dma350_cmdlink_set_des_trans_nonsecure(&cmdlink1_cfg);
    dma350_cmdlink_set_src_trans_privileged(&cmdlink1_cfg);
    dma350_cmdlink_set_des_trans_privileged(&cmdlink1_cfg);
    /* Set destination to CLCD register */
    dma350_cmdlink_set_desaddr32(&cmdlink1_cfg, (uint32_t) &p_clcd->char_dat);
    /* We perform a 2D copy with matching source and destination sizes */
    dma350_cmdlink_set_ytype(&cmdlink1_cfg, DMA350_CH_YTYPE_CONTINUE);
    /* Because of the endian swap, the transfer size is 1 byte */
    dma350_cmdlink_set_transize(&cmdlink1_cfg, DMA350_CH_TRANSIZE_8BITS);
    /* Set src x size to 2, and y size to  QUARTER_SIZE to copy 2*Q byte */
    /* And set the dst x size to 2*QUARTER_SIZE to match the bytecount with the src size */
    /* With FLOW_CTRL destriginmode, the destination ysize must be 1 */
    dma350_cmdlink_set_xsize32(&cmdlink1_cfg, sizeof(uint16_t), 2*QUARTER_SIZE);
    dma350_cmdlink_set_ysize16(&cmdlink1_cfg, QUARTER_SIZE, 1);
    /* Start at the end of the virtual row and go backwards to do endianness swap.
       Destination address is fixed (CLCD register) */
    dma350_cmdlink_set_srcaddr32(&cmdlink1_cfg, (uint32_t) &bitmap8_ptr[1]);
    dma350_cmdlink_set_xaddrinc(&cmdlink1_cfg, -1, 0);
    /* At the end of a row, advance the address with the size of the row.
       Higher numbers can be used to skip bytes from the source.
       Destination address is fixed (CLCD register) */
    dma350_cmdlink_set_yaddrstride(&cmdlink1_cfg, sizeof(uint16_t), 0);

    /* Enable destrigin, so the DMA will wait for a trigger before sending
       write transfers to the destination. */
    dma350_cmdlink_enable_destrigin(&cmdlink1_cfg);
    dma350_cmdlink_set_destriginmode(&cmdlink1_cfg, DMA350_CH_DESTRIGINMODE_PERIPH_FLOW_CTRL);
    /* Enable DESTRIGINWAIT interrupt, so the dma will trigger and irq when it
       is ready to send data. This is not needed if the peripheral is wired to
       the trigger interface of the DMA. In that case the peripheral can signal
       when it is ready to receive data (eg. half buffer event) without CPU
       intervention */
    dma350_cmdlink_enable_intr(&cmdlink1_cfg, DMA350_CH_INTREN_DESTRIGINWAIT);

    /* This is the number of transfers after the DMA expects a trigger from the
       destination, which represents the size after the CLCD signals transfer is
       complete, or that it is ready for this much data.
       This FVP implementation lacks such trigger, so the DMA is set up to send
       a full buffer amount of data, then signal the CPU to check if more data
       can be sent. */
    dma350_cmdlink_set_desmaxburstlen(&cmdlink1_cfg, 8);
    dma350_cmdlink_set_destriginblksize(&cmdlink1_cfg, 8);
    dma350_cmdlink_enable_linkaddr(&cmdlink1_cfg);

    /* Disable done interrupt */
    dma350_cmdlink_set_donetype(&cmdlink1_cfg, DMA350_CH_DONETYPE_NONE);
    dma350_cmdlink_disable_intr(&cmdlink1_cfg, DMA350_CH_INTREN_DONE);


    /* Setup CMD 2 */
    /* Copying second quarter */
    /* With the autoreload feature, command repeat could be set up.
       Unfortunately, when x address increment is negative, the address is not
       incremented properly after the last transaction in the FVP, due to a minor
       bug, thus needs to be set manually. */
    dma350_cmdlink_init(&cmdlink2_cfg);
    /* Set src x size to 2, and y size to  QUARTER_SIZE to copy 2*Q byte */
    /* And set the dst x size to 2*QUARTER_SIZE to match the bytecount with the src size */
    /* With FLOW_CTRL destriginmode, the destination ysize must be 1 */
    dma350_cmdlink_set_xsize32(&cmdlink2_cfg, sizeof(uint16_t), 2*QUARTER_SIZE);
    dma350_cmdlink_set_ysize16(&cmdlink2_cfg, QUARTER_SIZE, 1);
    /* Start from the second quarter (Q*2 bytes), end of the first row (+1) */
    dma350_cmdlink_set_srcaddr32(&cmdlink2_cfg, (uint32_t) &bitmap8_ptr[QUARTER_SIZE*sizeof(uint16_t) + 1]);
    dma350_cmdlink_enable_linkaddr(&cmdlink2_cfg);

    /* Setup CMD 3 */
    /* Copying third quarter */
    dma350_cmdlink_init(&cmdlink3_cfg);
    dma350_cmdlink_set_xsize32(&cmdlink3_cfg, sizeof(uint16_t), 2*QUARTER_SIZE);
    dma350_cmdlink_set_ysize16(&cmdlink3_cfg, QUARTER_SIZE, 1);
    dma350_cmdlink_set_srcaddr32(&cmdlink3_cfg, (uint32_t) &bitmap8_ptr[QUARTER_SIZE*sizeof(uint16_t)*2 + 1]);
    dma350_cmdlink_enable_linkaddr(&cmdlink3_cfg);

    /* Setup CMD 4 */
    /* Copying fourth quarter */
    dma350_cmdlink_init(&cmdlink4_cfg);
    dma350_cmdlink_set_xsize32(&cmdlink4_cfg, sizeof(uint16_t), 2*QUARTER_SIZE);
    dma350_cmdlink_set_ysize16(&cmdlink4_cfg, QUARTER_SIZE, 1);
    dma350_cmdlink_set_srcaddr32(&cmdlink4_cfg, (uint32_t) &bitmap8_ptr[QUARTER_SIZE*sizeof(uint16_t)*3 + 1]);
    dma350_cmdlink_enable_linkaddr(&cmdlink4_cfg);

    /* Setup Cleanup CMD */
    /* Clear the registers and set the DONE status at the end */
    dma350_cmdlink_init(&cmdlink_cleanup_cfg);
    dma350_cmdlink_set_regclear(&cmdlink_cleanup_cfg);
    /* Enable DONE interrupt after this command is finished */
    dma350_cmdlink_set_donetype(&cmdlink_cleanup_cfg, DMA350_CH_DONETYPE_END_OF_CMD);
    dma350_cmdlink_enable_intr(&cmdlink_cleanup_cfg, DMA350_CH_INTREN_DONE);
    /* This is the last command, disable further command linking */
    dma350_cmdlink_disable_linkaddr(&cmdlink_cleanup_cfg);

    /* Generate commands in reverse, because the commands needs to reference the
       next generated command: cmd1->cmd2->cmd3->cmd4->cmd_cleanup */
    /* cmd_cleanup will be the first command in the command buffer */
    cmd_cleanup = &cmd_buffer[0];
    /* This function generates the command link based on cmdlink_cleanup_cfg, to the
       address cmd_cleanup if it fits before the end of buffer. It returns the next
       available address after the generated command, or NULL, if the command
       would overrun the available buffer. */
    cmd4 = dma350_cmdlink_generate(&cmdlink_cleanup_cfg, cmd_cleanup, cmd_buffer_limit);
    if(cmd4 == NULL) {
        vLoggingPrintf("Out of cmd buffer");
        return;
    }

    /* Now that cmd_cleanup address is available, cmdlink4 can reference it */
    dma350_cmdlink_set_linkaddr32(&cmdlink4_cfg, (uint32_t) cmd_cleanup);
    cmd3 = dma350_cmdlink_generate(&cmdlink4_cfg, cmd4, cmd_buffer_limit);
    if(cmd3 == NULL) {
        vLoggingPrintf("Out of cmd buffer");
        return;
    }

    /* Now that cmd4 address is available, cmdlink3 can reference it */
    dma350_cmdlink_set_linkaddr32(&cmdlink3_cfg, (uint32_t) cmd4);
    cmd2 = dma350_cmdlink_generate(&cmdlink3_cfg, cmd3, cmd_buffer_limit);
    if(cmd2 == NULL) {
        vLoggingPrintf("Out of cmd buffer");
        return;
    }

    dma350_cmdlink_set_linkaddr32(&cmdlink2_cfg, (uint32_t) cmd3);
    cmd1 = dma350_cmdlink_generate(&cmdlink2_cfg, cmd2, cmd_buffer_limit);
    if(cmd1 == NULL) {
        vLoggingPrintf("Out of cmd buffer");
        return;
    }

    dma350_cmdlink_set_linkaddr32(&cmdlink1_cfg, (uint32_t) cmd2);
    check = dma350_cmdlink_generate(&cmdlink1_cfg, cmd1, cmd_buffer_limit);
    if(check == NULL) {
        vLoggingPrintf("Out of cmd buffer");
        return;
    }

    *first_command = cmd1;
    vLoggingPrintf("DMA commandlink setup complete");
    return;
}
