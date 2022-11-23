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
#include "string.h"
#include "stdbool.h"
#include "uart_stdout.h"
#include "print_log.h"

#include "FreeRTOS.h"
#include "task.h"
#include "FreeRTOS_IP.h"

#include "psa/protected_storage.h"
#include "psa/crypto.h"
#include "psa/update.h"
#include "psa/internal_trusted_storage.h"
#include "vad_an552.h"

#include "aws_dev_mode_key_provisioning.h"
#include "ota_provision.h"

#include "version/application_version.h"
#include "aws_demo.h"
#include "ota.h"

#define FIRST_BOOT_ITS_UID                  (1U)
#define BOOT_PATTERN                        (0x55)

extern uint32_t tfm_ns_interface_init(void);
extern void vApplicationIPInit(void);
extern int mbedtls_platform_set_calloc_free(
                                        void* (*calloc_func)(size_t, size_t),
                                        void (*free_func)(void *));
extern void publishToAWSTopic(const char *msg);

static void* prvCalloc(size_t xNmemb, size_t xSize);
static bool is_first_boot(void);
static void write_boot_pattern(void);

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

psa_key_handle_t xOTACodeVerifyKeyHandle = 0xAA;


static bool is_first_boot(void)
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    const psa_storage_uid_t uid = FIRST_BOOT_ITS_UID;
    uint8_t boot_pattern_in_its = 0;
    size_t read_data_length = 0;

    status = psa_its_get(uid, 0, 1, &boot_pattern_in_its,
                         &read_data_length);
    if(status != PSA_SUCCESS) {
        vLoggingPrintf("Could not read ITS to determine boot counter");
        vLoggingPrintf("Assuming first boot");
        return true;
    }

    if(boot_pattern_in_its == BOOT_PATTERN) {
        vLoggingPrintf("Boot pattern in ITS matches, not first boot");
        return false;
    }
    else {
        vLoggingPrintf("Boot pattern in ITS doesn't match, first boot");
        return true;
    }
}

static void write_boot_pattern(void)
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    const psa_storage_uid_t uid = FIRST_BOOT_ITS_UID;
    const psa_storage_create_flags_t flags = PSA_STORAGE_FLAG_NONE;
    uint8_t first_boot_pattern = BOOT_PATTERN;

    /* Write the pattern to ITS */
    status = psa_its_set(uid, 1, &first_boot_pattern, flags);
    if(status == PSA_SUCCESS) {
        vLoggingPrintf("Boot pattern has been written to the ITS");
    }
    else {
        vLoggingPrintf("Couldn't write boot pattern to ITS");
    }
}

static void mainTask(void *pvParameters)
{
    uint32_t vad_status;
    uint32_t vad_freq;
    OtaState_t ota_state;
    TickType_t base_tick, curr_tick;
    char message[256];

#ifdef VAD_AN552_NO_CONNECTIVITY
    while(1) {
        vad_an552_start_vad();

        do {
            vad_an552_query_vad(&vad_status);
        } while (vad_status != VAD_VOICE_RECORDED);

        vad_an552_get_freq(&vad_freq);

        vLoggingPrintf("Voice detected with most energy at %d Hz", vad_freq);
    }
#else
    while(1) {
        vLoggingPrintf("==== Start OTA task ====");
        DEMO_RUNNER_RunDemos();

        do {
            vTaskDelay(pdMS_TO_TICKS(10));
            ota_state = OTA_GetState();
        }
        while (ota_state == OtaAgentStateInit ||
               ota_state == OtaAgentStateReady ||
               ota_state == OtaAgentStateStopped ||
               ota_state == OtaAgentStateRequestingJob);

        vTaskDelay(pdMS_TO_TICKS(5000));

        if (OtaAgentStateWaitingForJob == OTA_GetState()) {
            vLoggingPrintf("==== Stop OTA task ====");

            OTA_Shutdown(0, 1);
            while (xTaskGetHandle("iot_thread") != NULL) {
                vTaskDelay(pdMS_TO_TICKS(100));
            }

            base_tick = xTaskGetTickCount();

            vLoggingPrintf("==== Start listening ====");
            vad_an552_start_vad();

            while(1) {
                vad_an552_query_vad(&vad_status);
                if (vad_status == VAD_VOICE_RECORDED) {
                    vad_an552_get_freq(&vad_freq);

                    vLoggingPrintf("Voice detected with most energy at %d Hz",
                                   vad_freq);
                    vLoggingPrintf("==== Send message to cloud ====");
                    sprintf(message, "Voice detected with most energy at %d Hz",
                            vad_freq);
                    publishToAWSTopic(message);

                    /* Message sending takes some time so timeout checked
                     * before restarting the mic algorithm. */
                    curr_tick = xTaskGetTickCount();
                    if ((curr_tick - base_tick) > pdMS_TO_TICKS(60000)) {
                        vad_an552_stop_vad();
                        break;
                    }

                    vLoggingPrintf("==== Start listening ====");
                    vad_an552_start_vad();
                }

                curr_tick = xTaskGetTickCount();
                if ((curr_tick - base_tick) > pdMS_TO_TICKS(60000)) {
                    vLoggingPrintf("==== Stop listening ====");
                    vad_an552_stop_vad();
                    break;
                }
            }
        } else {
            /* OTA started, nothing to do */
            while (1) {
                vTaskDelay(pdMS_TO_TICKS(10000));
            }
        }
    }
#endif
}

int main()
{
    stdio_init();
    vUARTLockInit();
    tfm_ns_interface_init();
    GetImageVersionPSA(FWU_COMPONENT_ID_FULL);
    vLoggingPrintf("Application firmware version: %d.%d.%d",
                   appFirmwareVersion.u.x.major,
                   appFirmwareVersion.u.x.minor,
                   appFirmwareVersion.u.x.build);

#ifdef VAD_AN552_NO_CONNECTIVITY
    xTaskCreate(mainTask, "main task", configMINIMAL_STACK_SIZE*2, NULL,
                configMAX_PRIORITIES-2, NULL);
#else
    mbedtls_platform_set_calloc_free(prvCalloc, vPortFree);

    if(is_first_boot()) {
        vDevModeKeyProvisioning();
        ota_privision_code_signing_key(&xOTACodeVerifyKeyHandle);
        write_boot_pattern();
    }

    /* Initialise the RTOS's TCP/IP stack.  The tasks that use the network
    are created in the vApplicationIPNetworkEventHook() hook function
    below.  The hook function is called when the network connects. */
    vApplicationIPInit();
#endif

    vLoggingPrintf("Starting FreeRTOS scheduler");
#ifndef VAD_AN552_NO_CONNECTIVITY
    vLoggingPrintf("Waiting for network");
#endif
    /* Start the scheduler itself. */
    vTaskStartScheduler();

    while (1)
    {
    }
}

void vApplicationIPNetworkEventHook(eIPCallbackEvent_t eNetworkEvent)
{
#ifndef VAD_AN552_NO_CONNECTIVITY
    if (eNetworkEvent == eNetworkUp) {
        vLoggingPrintf("Network connection established");
        xTaskCreate(mainTask, "main task", configMINIMAL_STACK_SIZE*2, NULL,
        configMAX_PRIORITIES-4, NULL);
    }
#endif
}

/* Functions needed for mbedtls build */
static void * prvCalloc(size_t xNmemb,
                        size_t xSize)
{
    void * pvNew = pvPortMalloc(xNmemb * xSize);

    if( NULL != pvNew ) {
        memset(pvNew, 0, xNmemb * xSize);
    }

    return pvNew;
}

int mbedtls_hardware_poll(void *data,
                          unsigned char *output, size_t len, size_t *olen)
{
    psa_status_t status;

    (void) (data);

    if (output == NULL || olen == NULL) {
        return -1;
    }

    status = psa_generate_random(output, len);
    if (status != PSA_SUCCESS) {
        return -1;
    }

    *olen = len;

    return 0;
}
