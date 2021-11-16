/*
 * FreeRTOS V202104.00
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * @file ota_config.h
 * @brief OTA user configurable settings.
 */

#ifndef OTA_CONFIG_H_
#define OTA_CONFIG_H_

/* Log configuration */
#include "logging_levels.h"
#ifndef LOG_LEVEL
    #define LOG_LEVEL    LOG_INFO
#endif
#include "logging_stack.h"

/* errno is required for OTA sources */
extern int errno;

/**
 * @brief Log base 2 of the size of the file data block message (excluding the
 * header).
 *
 * <b>Possible values:</b> Any unsigned 32 integer. <br>
 */
#define otaconfigLOG2_FILE_BLOCK_SIZE       12UL

/**
 * @brief Size of the file data block message (excluding the header).
 */
#define otaconfigFILE_BLOCK_SIZE            (1UL << otaconfigLOG2_FILE_BLOCK_SIZE)

/**
 * @brief The protocol selected for OTA control operations.
 *
 * @note This configurations parameter sets the default protocol for all the
 * OTA control operations like requesting OTA job, updating the job status etc.
 *
 * @note Only MQTT is supported at this time for control operations.
 *
 * <b>Possible values:</b> OTA_CONTROL_OVER_MQTT <br>
 */
#define configENABLED_CONTROL_PROTOCOL      (OTA_CONTROL_OVER_MQTT)

/**
 * @brief The protocol selected for OTA data operations.
 *
 * @note This configurations parameter sets the protocols selected for the data
 * operations like requesting file blocks from the service.
 *
 * <b>Possible values:</b><br>
 * Enable data over MQTT - ( OTA_DATA_OVER_MQTT ) <br>
 * Enable data over HTTP - ( OTA_DATA_OVER_HTTP ) <br>
 * Enable data over both MQTT & HTTP - ( OTA_DATA_OVER_MQTT | OTA_DATA_OVER_HTTP ) <br>
 */
#define configENABLED_DATA_PROTOCOLS        (OTA_DATA_OVER_MQTT)

/**
 * @brief The preferred protocol selected for OTA data operations.
 *
 * @note Primary data protocol will be the protocol used for downloading file
 * if more than one protocol is selected while creating OTA job.
 *
 * <b>Possible values:</b><br>
 * Data over MQTT - ( OTA_DATA_OVER_MQTT ) <br>
 * Data over HTTP - ( OTA_DATA_OVER_HTTP ) <br>
 */
#define configOTA_PRIMARY_DATA_PROTOCOL     (OTA_DATA_OVER_MQTT)

#endif /* OTA_CONFIG_H_ */
