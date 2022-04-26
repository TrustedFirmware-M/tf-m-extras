/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "Driver_SPI.h"
#include "cmsis.h"
#include "stm32l5xx_hal.h"
/* board configuration  */
#include "board.h"
#ifndef ARG_UNUSED
#define ARG_UNUSED(arg)  (void)arg
#endif /* ARG_UNUSED */
#define SPI_DRV_VERSION  ARM_DRIVER_VERSION_MAJOR_MINOR(1, 0)


/* Driver Version */
static const ARM_DRIVER_VERSION DriverVersion = {
    ARM_SPI_API_VERSION,
    SPI_DRV_VERSION
};

/* Driver Capabilities */
static const ARM_SPI_CAPABILITIES DriverCapabilities = {
    0,  // Simplex Mode (Master and Slave)
    0,  // TI Synchronous Serial Interface
    0,  // Microwire Interface
    1   // Signal Mode Fault event: \ref ARM_SPI_EVENT_MODE_FAULT
};

static ARM_SPI_STATUS status = {
    0,
    0,
    0
};

/**
  \fn          ARM_DRIVER_VERSION SPI_GetVersion (void)
  \brief       Get SPI driver version.
  \return      \ref ARM_DRV_VERSION
*/
static ARM_DRIVER_VERSION SPI_GetVersion (void)
{
    return DriverVersion;
}

/**
  \fn          ARM_SPI_CAPABILITIES SPI_GetCapabilities (void)
  \brief       Get driver capabilities.
  \return      \ref ARM_SPI_CAPABILITIES
*/
static ARM_SPI_CAPABILITIES SPI_GetCapabilities (void)
{
    return DriverCapabilities;
}

static SPI_HandleTypeDef  hspi3;
uint32_t spi_timeout = 1200;
/**
  \fn          int32_t SPI_Initialize (ARM_SPI_SignalEvent_t cb_event)
  \brief       Initialize SPI Interface.
  \param[in]   cb_event  Pointer to \ref ARM_SPI_SignalEvent
  \return      \ref execution_status
*/
static int32_t SPI3_Initialize (ARM_SPI_SignalEvent_t cb_event)
{
    /* SPI3 parameter configuration*/
    ((void)cb_event);
#if !defined(__DOMAIN_NS)
    GPIO_InitTypeDef GPIO_Init = {0};

    /* Configure SPI cs as alternate function */
    SPI_CS_GPIO_CLK_ENABLE();
    GPIO_Init.Pin       = SPI_CS_PIN;
    GPIO_Init.Mode      = GPIO_MODE_OUTPUT_PP;
    GPIO_Init.Speed     = GPIO_SPEED_FREQ_MEDIUM;
    GPIO_Init.Pull      = GPIO_PULLUP;
    HAL_GPIO_Init(SPI_CS_GPIO_PORT, &GPIO_Init);
    HAL_GPIO_WritePin(SPI_CS_GPIO_PORT, SPI_CS_PIN, GPIO_PIN_SET);

    SPI_CLK_ENABLE();
    HAL_PWREx_EnableVddIO2();
    /* Configure SPI miso as alternate function */
    SPI_MISO_GPIO_CLK_ENABLE();
    GPIO_Init.Pin       = SPI_MISO_PIN;
    GPIO_Init.Mode      = GPIO_MODE_AF_PP;
    GPIO_Init.Speed     = GPIO_SPEED_FREQ_MEDIUM;
    GPIO_Init.Pull      = GPIO_PULLUP;
    GPIO_Init.Alternate = SPI_MISO_AF;
    HAL_GPIO_Init(SPI_MISO_GPIO_PORT, &GPIO_Init);
    /* Configure SPI mosi as alternate function */
    SPI_MOSI_GPIO_CLK_ENABLE();
    GPIO_Init.Pin       = SPI_MOSI_PIN;
    GPIO_Init.Mode      = GPIO_MODE_AF_PP;
    GPIO_Init.Speed     = GPIO_SPEED_FREQ_MEDIUM;
    GPIO_Init.Pull      = GPIO_PULLUP;
    GPIO_Init.Alternate = SPI_MOSI_AF;
    HAL_GPIO_Init(SPI_MOSI_GPIO_PORT, &GPIO_Init);
    /* Configure SPI sck as alternate function */
    SPI_SCK_GPIO_CLK_ENABLE();
    GPIO_Init.Pin       = SPI_SCK_PIN;
    GPIO_Init.Mode      = GPIO_MODE_AF_PP;
    GPIO_Init.Speed     = GPIO_SPEED_FREQ_MEDIUM;
    GPIO_Init.Pull      = GPIO_PULLUP;
    GPIO_Init.Alternate = SPI_SCK_AF;
    HAL_GPIO_Init(SPI_SCK_GPIO_PORT, &GPIO_Init);

#endif /* __DOMAIN_NS */
    hspi3.Instance = SPI3;
    hspi3.Init.Mode = SPI_MODE_MASTER;
    hspi3.Init.Direction = SPI_DIRECTION_2LINES;
    hspi3.Init.DataSize = SPI_DATASIZE_8BIT;
    hspi3.Init.CLKPolarity = SPI_POLARITY_LOW;
    hspi3.Init.CLKPhase = SPI_PHASE_1EDGE;
    hspi3.Init.NSS = SPI_NSS_SOFT;
    hspi3.Init.BaudRatePrescaler = SPI_BAUDRATEPRESCALER_16;
    hspi3.Init.FirstBit = SPI_FIRSTBIT_MSB;
    hspi3.Init.TIMode = SPI_TIMODE_DISABLE;
    hspi3.Init.CRCCalculation = SPI_CRCCALCULATION_DISABLE;
    hspi3.Init.CRCPolynomial = 7;
    hspi3.Init.CRCLength = SPI_CRC_LENGTH_DATASIZE;
    hspi3.Init.NSSPMode = SPI_NSS_PULSE_ENABLE;
    if (HAL_SPI_Init(&hspi3) != HAL_OK) {
        return ARM_DRIVER_ERROR;
    }
    return ARM_DRIVER_OK;
}


static int32_t SPI3_Uninitialize(void)
{
    /* Nothing to be done */
    if (HAL_SPI_DeInit(&hspi3) != HAL_OK) {
        return ARM_DRIVER_ERROR;
    }
    return ARM_DRIVER_OK;
}


static int32_t SPI3_PowerControl(ARM_POWER_STATE state)
{
    return ARM_DRIVER_OK;
}



/**
  \fn          int32_t SPI_Send (const void *data, uint32_t num)
  \brief       Start sending data to SPI transmitter.
  \param[in]   data  Pointer to buffer with data to send to SPI transmitter
  \param[in]   num   Number of data items to send
  \return      \ref execution_status
*/
static int32_t SPI3_Send (const void *data, uint32_t num)
{
    if ((data == NULL) || (num == 0U)) {
        return ARM_DRIVER_ERROR_PARAMETER;
    }
    if ((HAL_SPI_GetState(&hspi3) != HAL_SPI_STATE_READY)) {
        return ARM_DRIVER_ERROR_BUSY;
    }
    HAL_SPI_Transmit(&hspi3, data, num, spi_timeout);
    return ARM_DRIVER_OK;
}

/**
  \fn          int32_t SPI_Receive (void *data, uint32_t num)
  \brief       Start receiving data from SPI receiver.
  \param[out]  data  Pointer to buffer for data to receive from SPI receiver
  \param[in]   num   Number of data items to receive
  \return      \ref execution_status
*/
static int32_t SPI3_Receive (void *data, uint32_t num)
{
    if ((data == NULL) || (num == 0U)) {
        return ARM_DRIVER_ERROR_PARAMETER;
    }
    if ((HAL_SPI_GetState(&hspi3) != HAL_SPI_STATE_READY)) {
        return ARM_DRIVER_ERROR_BUSY;
    }
    HAL_SPI_Receive(&hspi3, data, num, spi_timeout);
    return ARM_DRIVER_OK;
}



static int32_t SPI3_Transfer (const void *data_out, void *data_in, uint32_t num)
{
//    ARG_UNUSED(data_out);
//    ARG_UNUSED(data_in);
//    ARG_UNUSED(num);
    HAL_SPI_Transmit(&hspi3, data_out, num, spi_timeout);
    HAL_SPI_Receive(&hspi3, data_in, num, spi_timeout);
    return ARM_DRIVER_OK;
}


static uint32_t SPI3_GetDataCount (void)
{
    return 0;
}
/**
  \fn          int32_t SPI_Control (uint32_t control, uint32_t arg)
  \brief       Control SPI Interface.
  \param[in]   control  Operation
  \param[in]   arg      Argument of operation (optional)
  \return      common \ref execution_status and driver specific \ref spi_execution_status
*/
static int32_t SPI3_Control (uint32_t control, uint32_t arg)
{
    switch (control & ARM_SPI_CONTROL_Msk) {
    // Control Slave Select; arg = 0:inactive, 1:active
    case ARM_SPI_CONTROL_SS:
        if (arg == ARM_SPI_SS_INACTIVE) {
            HAL_GPIO_WritePin(SPI_CS_GPIO_PORT, SPI_CS_PIN, GPIO_PIN_SET);
        } else {
            HAL_GPIO_WritePin(SPI_CS_GPIO_PORT, SPI_CS_PIN, GPIO_PIN_RESET);
        }
        return ARM_DRIVER_OK;
    default:
        return ARM_DRIVER_ERROR_UNSUPPORTED;
    }
}

static ARM_SPI_STATUS SPI3_GetStatus(void)
{
    ARM_SPI_STATUS status = {0, 0, 0};
    return status;
}

// SPI3 Driver Control Block
ARM_DRIVER_SPI Driver_SPI3 = {
    SPI_GetVersion,
    SPI_GetCapabilities,
    SPI3_Initialize,
    SPI3_Uninitialize,
    SPI3_PowerControl,
    SPI3_Send,
    SPI3_Receive,
    SPI3_Transfer,
    SPI3_GetDataCount,
    SPI3_Control,
    SPI3_GetStatus
};
