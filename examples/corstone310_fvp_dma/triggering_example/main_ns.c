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


#include "stdio.h"
#include "uart_stdout.h"
#include "dma350_ch_drv.h"
#include "device_cfg.h"
#include "platform_base_address.h"
#include "uart_cmsdk_reg_map.h"
#include "uart_cmsdk_drv.h"
#include "cmsis.h"
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

#define BUFFERING_LEN       (10u)

#define IN_ARRAY_LEN        (BUFFERING_LEN)
#define OUT_ARRAY_LEN       (BUFFERING_LEN)

extern struct dma350_ch_dev_t DMA350_DMA0_CH1_DEV_NS;
extern struct uart_cmsdk_dev_t UART0_CMSDK_DEV_NS;
extern struct uart_cmsdk_dev_t UART1_CMSDK_DEV_NS;

static uint8_t in_array[IN_ARRAY_LEN];
static uint8_t out_array[OUT_ARRAY_LEN];

/* DMA Channel Device structure definition */
struct dma350_ch_dev_t DMA350_DMA0_CH1_DEV_NS = {
    .cfg = {.ch_base = (DMACH_TypeDef *)(DMA_350_BASE_NS + 0x1100UL),
            .channel = 1},
    .data = {0}};

/* UART Device structure definition */
static const struct uart_cmsdk_dev_cfg_t UART1_CMSDK_DEV_CFG_NS = {
    .base = UART1_BASE_NS,
    .default_baudrate = DEFAULT_UART_BAUDRATE
};
static struct uart_cmsdk_dev_data_t UART1_CMSDK_DEV_DATA_NS = {
    .state = 0,
    .system_clk = 0,
    .baudrate = 0
};
struct uart_cmsdk_dev_t UART1_CMSDK_DEV_NS = {
    &(UART1_CMSDK_DEV_CFG_NS),
    &(UART1_CMSDK_DEV_DATA_NS)
};


static enum uart_cmsdk_error_t init_uart(void);
static void init_dma_trans_security_privilege(struct dma350_ch_dev_t *ch_dev);
static void init_dma_trans_sizes(struct dma350_ch_dev_t *ch_dev);
static void init_dma_interrupt(struct dma350_ch_dev_t *ch_dev);
static void init_dma_for_uart_rx(struct dma350_ch_dev_t *ch_dev);
static void init_dma_for_uart_tx(struct dma350_ch_dev_t *ch_dev);
static void process_data(void);

void dma_ch_irq_handler()
{
    /* Do nothing, just clear the interrupt source */
    if(dma350_ch_is_intr_set(&DMA350_DMA0_CH1_DEV_NS, DMA350_CH_INTREN_DONE)) {
        /* All transactions finished */
        dma350_ch_clear_stat(&DMA350_DMA0_CH1_DEV_NS, DMA350_CH_STAT_DONE);
    }
}

int main()
{
    union dma350_ch_status_t status;
    struct dma350_ch_dev_t *ch_dev = &DMA350_DMA0_CH1_DEV_NS;

    stdio_init();

    printf("\r\n\r\nStarting DMA350 Triggering example\r\n\r\n\r\n");

    if(init_uart() != UART_CMSDK_ERR_NONE) {
        return 1;
    }

    enum dma350_ch_error_t ch_err = dma350_ch_init(ch_dev);
    if(ch_err != DMA350_CH_ERR_NONE) {
        printf("DMA CH init failed: 0x%x\r\n", ch_err);
        return 1;
    }

    while(1) {
        printf("---------------------------------------------------------\r\n");
        printf("---------------------------------------------------------\r\n");
        printf("Configure DMA350 for TX on UART1, then CPU goes to sleep.\r\n");
        printf("Type in 10 character to this terminal\r\n");
        init_dma_for_uart_rx(ch_dev);
        __WFI();

        printf("10 Characterer received, waking up to process the data \r\n");
        /* Disable srctrig_in, as it is not needed for the next transaction */
        dma350_ch_disable_srctrigin(ch_dev);

        process_data();
        printf("Data processed\r\n");

        printf("Configure DMA350 for TX on UART1, then CPU goes to sleep \r\n");
        init_dma_for_uart_tx(ch_dev);
        __WFI();
        /* Disable destrigin, as it is not needed for the next transaction */
        dma350_ch_disable_destrigin(ch_dev);
    }

    return 0;
}

static void init_dma_for_uart_rx(struct dma350_ch_dev_t *ch_dev)
{
    struct uart_cmsdk_reg_map_t* p_uart0 =
                       (struct uart_cmsdk_reg_map_t*)UART0_CMSDK_DEV_NS.cfg->base;

    init_dma_trans_security_privilege(ch_dev);

    /* At first we want to copy the incoming data to an array */
    /* Copy from Uart 0 */
    dma350_ch_set_src(ch_dev, (uint32_t)&p_uart0->data);
    /* Copy to in buffer */
    dma350_ch_set_des(ch_dev, (uint32_t)in_array);

    init_dma_trans_sizes(ch_dev);

    /* Do not increment the src address, as UART's data register doesn't change.
     * Increment the in_array index by one, after each transaction
     */
    dma350_ch_set_xaddr_inc(ch_dev, 0, 1);

    /* Enable source trigger. The UART is going to signal when the
     * transaction can happen
     */
    dma350_ch_enable_srctrigin(ch_dev);
    /* Select 0. trigger input, where the UART0 RX is connected */
    dma350_ch_set_srctriginsel(ch_dev, 0);
    /* Set that the UART is going to control the flow */
    dma350_ch_set_srctriginmode(ch_dev, DMA350_CH_SRCTRIGINMODE_PERIPH_FLOW_CTRL);
    dma350_ch_set_srctrigintype(ch_dev, DMA350_CH_SRCTRIGINTYPE_HW);
    dma350_ch_set_srctriginblksize(ch_dev, 0);

    init_dma_interrupt(ch_dev);

    /* Start the command */
    dma350_ch_cmd(ch_dev, DMA350_CH_CMD_ENABLECMD);
}

static void init_dma_for_uart_tx(struct dma350_ch_dev_t *ch_dev)
{
    struct uart_cmsdk_reg_map_t* p_uart1 =
                       (struct uart_cmsdk_reg_map_t*)UART1_CMSDK_DEV_NS.cfg->base;

    init_dma_trans_security_privilege(ch_dev);

    /* Move the data from the array to a different UART's TX */
    /* Copy from the out buffer */
    dma350_ch_set_src(ch_dev, (uint32_t)out_array);
    /* Copy to UART1's data register */
    dma350_ch_set_des(ch_dev, (uint32_t)&p_uart1->data);

    init_dma_trans_sizes(ch_dev);

    /* Do not increment the dst address, as UART's data register doesn't change.
     * Increment the out_array index by one, after each transaction
     */
    dma350_ch_set_xaddr_inc(ch_dev, 1, 0);

    /* Enable destination trigger. The UART1 is going to signal when the
     * transaction can happen
     */
    dma350_ch_enable_destrigin(ch_dev);
    /* Select 3. trigger input, where the UART1 TX is connected */
    dma350_ch_set_destriginsel(ch_dev, 3);
    /* Set that the UART is going to control the flow */
    dma350_ch_set_destriginmode(ch_dev, DMA350_CH_DESTRIGINMODE_PERIPH_FLOW_CTRL);
    dma350_ch_set_destrigintype(ch_dev, DMA350_CH_DESTRIGINTYPE_HW);
    dma350_ch_set_destriginblksize(ch_dev, 0);

    init_dma_interrupt(ch_dev);

    /* Start the command */
    dma350_ch_cmd(ch_dev, DMA350_CH_CMD_ENABLECMD);
    /* For the first time, the DMA has to be triggered manually,
     * because the UART TX won't send trigger without previous transfer
     */
    dma350_ch_cmd(ch_dev, DMA350_CH_CMD_DESSWTRIGINREQ);

}

static void process_data(void)
{
    /* Placeholder processing, which could be substituted */

    /* Reverse the incoming data */
    for(uint32_t i = 0; i < BUFFERING_LEN; i++) {
        out_array[BUFFERING_LEN - 1 - i] = in_array[i];
    }
}

static enum uart_cmsdk_error_t init_uart(void)
{
    /* UART0 is already initialized by TFM, so only initialize UART1 */
    enum uart_cmsdk_error_t err = UART_CMSDK_ERR_NONE;
    err = uart_cmsdk_init(&UART1_CMSDK_DEV_NS, PeripheralClock);
    if(err != UART_CMSDK_ERR_NONE) {
        return err;
    }

    err = uart_cmsdk_set_baudrate(&UART1_CMSDK_DEV_NS, UART1_CMSDK_DEV_NS.cfg->default_baudrate);
    if(err != UART_CMSDK_ERR_NONE) {
        return err;
    }

    /* Enable RX interrupt for UART0 */
    uart_cmsdk_irq_rx_enable(&UART0_CMSDK_DEV_NS);
    if(err != UART_CMSDK_ERR_NONE) {
        return err;
    }

    /* Enable TX interrupt for UART1 */
    uart_cmsdk_irq_tx_enable(&UART1_CMSDK_DEV_NS);
    if(err != UART_CMSDK_ERR_NONE) {
        return err;
    }

    return err;
}

static void init_dma_trans_security_privilege(struct dma350_ch_dev_t *ch_dev)
{
    /* Set the transactions security and privilege levels */
    /* The arrays and UARTs are non-secure, and the application runs in
     * privileged mode
     */
    dma350_ch_set_src_trans_nonsecure(ch_dev);
    dma350_ch_set_des_trans_nonsecure(ch_dev);
    dma350_ch_set_src_trans_privileged(ch_dev);
    dma350_ch_set_des_trans_privileged(ch_dev);
}

static void init_dma_trans_sizes(struct dma350_ch_dev_t *ch_dev)
{
    /* Set xsize32 to copy BUFFERING_LEN bytes, then set the DMA channel to DONE */
    dma350_ch_set_xsize32(ch_dev, BUFFERING_LEN, BUFFERING_LEN);
    /* Set transize to 8 bits/transfer */
    dma350_ch_set_transize(ch_dev, DMA350_CH_TRANSIZE_8BITS);
    /* Perform an 1D copy, where source and destination have the same size */
    dma350_ch_set_xtype(ch_dev, DMA350_CH_XTYPE_CONTINUE);
    dma350_ch_set_ytype(ch_dev, DMA350_CH_YTYPE_DISABLE);

}

static void init_dma_interrupt(struct dma350_ch_dev_t *ch_dev)
{
    /* Enable donetype to generate an interrupt after finish, and leave WFI() */
    dma350_ch_set_donetype(ch_dev, DMA350_CH_DONETYPE_END_OF_CMD);
    dma350_ch_enable_intr(ch_dev, DMA350_CH_INTREN_DONE);
    /* Enable the interrupts in the NVIC as well */
    NVIC_SetVector(DMA_CHANNEL_0_IRQn + ch_dev->cfg.channel, (uint32_t) dma_ch_irq_handler);
    NVIC_EnableIRQ(DMA_CHANNEL_0_IRQn + ch_dev->cfg.channel);
}

