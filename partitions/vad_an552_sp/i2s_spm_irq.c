/*
 * Copyright (c) 2021-2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdint.h>

#include "cmsis.h"
#include "ffm/interrupt.h"
#include "load/interrupt_defs.h"
#include "tfm_peripherals_def.h"

/* Structure for IRQ handling by SPM */
static struct irq_t i2s_irq = {0};

void I2S_Handler(void)
{
    spm_handle_interrupt(i2s_irq.p_pt, i2s_irq.p_ildi);
}

enum tfm_hal_status_t i2s_irqn_init(void *p_pt,
                                    struct irq_load_info_t *p_ildi)
{
    i2s_irq.p_ildi = p_ildi;
    i2s_irq.p_pt = p_pt;

    NVIC_SetPriority(I2S_IRQn, DEFAULT_IRQ_PRIORITY);
    NVIC_ClearTargetState(I2S_IRQn);
    NVIC_DisableIRQ(I2S_IRQn);

    return TFM_HAL_SUCCESS;
}
