/*
 * Copyright (c) 2021-2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdint.h>

#include "psa/service.h"
#include "psa_manifest/vad_an552_sp.h"
#include "vad_an552_defs.h"
#include "vad_an552.h"
#include "timeout.h"
#include "tfm_sp_log.h"
#include "vad_an552_device_definition.h"
#include "audio_codec_mps3.h"
#include "cmsis.h"
#include "tfm_peripherals_def.h"

/* CMSIS DSP implementations */
#include "dsp/statistics_functions.h"
#include "dsp/transform_functions.h"
#include "dsp/complex_math_functions.h"

/* Voice activity detection algorithm and related defines */
extern void vad_estimation(long *command, long* vad, short *inputData,
                           long nbSamples, long samplingRate);
#define INIT_VAD    1
#define PROC_VAD    2
#define FS          48000

/* For voice recording and FFT calculation */
#define RECORDING_SIZE 4096
int16_t sample_buffer[RECORDING_SIZE];
uint32_t sample_buffer_end_idx; /* Index of last element in sample_buffer */
q15_t fft_result[2 * RECORDING_SIZE];
q15_t fft_magnitude[RECORDING_SIZE];

/* Status of the secure partition */
uint32_t vad_status = VAD_STOPPED;

void start_listening()
{
    audio_i2s_mps3_set_fifo_reset(&MPS3_I2S_DEV_S);
    wait_ms(1);
    audio_i2s_mps3_clear_fifo_reset(&MPS3_I2S_DEV_S);
    audio_i2s_mps3_enable_rxbuf(&MPS3_I2S_DEV_S);
    audio_i2s_mps3_enable_rxinterrupt(&MPS3_I2S_DEV_S);
}

void stop_listening()
{
    audio_i2s_mps3_disable_rxbuf(&MPS3_I2S_DEV_S);
    audio_i2s_mps3_disable_rxinterrupt(&MPS3_I2S_DEV_S);
    wait_ms(1);
}

psa_flih_result_t i2s_flih(void)
{
    short current_sample;
    long voice_activity = 0;
    static long command = PROC_VAD;

    while (audio_i2s_mps3_is_rx_buffer_empty(&MPS3_I2S_DEV_S) == false) {
        /* Only right channel used, left channel is dropped with the casting */
        current_sample = (short) audio_i2s_mps3_get_rxbuf(&MPS3_I2S_DEV_S);
        if (vad_status == VAD_NO_VOICE_DETECTED) {
            vad_estimation(&command, &voice_activity, &current_sample, 1, FS);

            if (voice_activity == 1) {
                vad_status = VAD_RECORDING;
                sample_buffer_end_idx = 0;
            }

        } else if (vad_status == VAD_RECORDING){
            sample_buffer[sample_buffer_end_idx++] = current_sample;

            if (sample_buffer_end_idx ==
                (sizeof(sample_buffer) / sizeof(sample_buffer[0]))) {
                stop_listening();
                vad_status = VAD_VOICE_RECORDED;
            }
        } else {
            stop_listening();
        }
    }

    return PSA_FLIH_NO_SIGNAL;
}

static psa_status_t start_vad()
{
    long command = INIT_VAD;

    vad_estimation(&command, 0, 0, 0, FS);
    vad_status = VAD_NO_VOICE_DETECTED;
    start_listening();
    psa_irq_enable(I2S_SIGNAL);

    return PSA_SUCCESS;
}

static psa_status_t query_vad(const psa_msg_t *msg)
{
    psa_write(msg->handle, 0, &vad_status, sizeof(vad_status));

    return PSA_SUCCESS;
}

static psa_status_t get_freq(const psa_msg_t *msg)
{
    uint32_t freq = 0;
    arm_rfft_instance_q15 fft_instance;
    arm_status dsp_status;
    q15_t max_value;
    uint32_t max_index;

    if (vad_status == VAD_VOICE_RECORDED) {
        dsp_status = arm_rfft_init_q15(&fft_instance, RECORDING_SIZE, 0, 1);

        /* No need for conversation between int16_t and q15_t as we are only
         * interested in which frequency bin has the highest energy.
         */
        arm_rfft_q15(&fft_instance, (q15_t *) sample_buffer, fft_result);
        arm_cmplx_mag_q15(fft_result, fft_magnitude, RECORDING_SIZE);
        arm_max_q15(fft_magnitude, RECORDING_SIZE/2, &max_value, &max_index);

        if (max_value != 0) {
            /* A real maximum was found, returning the lower end of the maximum
             * frequency bin.
             */
            freq = (FS / RECORDING_SIZE) * max_index;
        } else {
            freq = 0;
        }

        psa_write(msg->handle, 0, &freq, sizeof(freq));

        /* The FFT calculation updates the recorded sample, so we move to the
         * intitial state.
         */
        vad_status = VAD_STOPPED;

        return PSA_SUCCESS;
    } else {
        return PSA_ERROR_BAD_STATE;
    }
}

static psa_status_t stop_vad()
{
    psa_irq_disable(I2S_SIGNAL);
    stop_listening();
    vad_status = VAD_STOPPED;

    return PSA_SUCCESS;
}

static void vad_signal_handle(psa_signal_t signal)
{
    psa_msg_t msg;
    psa_status_t status;

    status = psa_get(signal, &msg);
    if (status != PSA_SUCCESS) {
        return;
    }

    switch (msg.type) {
    case VAD_AN552_START:
        status = start_vad();
        psa_reply(msg.handle, status);
        break;
    case VAD_AN552_QUERY:
        status = query_vad(&msg);
        psa_reply(msg.handle, status);
        break;
    case VAD_AN552_GET_FREQ:
        status = get_freq(&msg);
        psa_reply(msg.handle, status);
        break;
    case VAD_AN552_STOP:
        status = stop_vad();
        psa_reply(msg.handle, status);
        break;
    default:
        /* Invalid message type */
        status = PSA_ERROR_PROGRAMMER_ERROR;
        psa_reply(msg.handle, status);
        break;
    }
}

void vad_main(void)
{
    psa_signal_t signals;

    /* Audio initialization */
    audio_codec_mps3_init(&I2C0_SBCON_DEV_S, &MPS3_I2S_DEV_S);

    /* Set Rx Buffer Irq Water Level. If less than 1 word space is available,
       IRQ is triggered */
    audio_i2s_mps3_set_rx_buff_water_lvl(&MPS3_I2S_DEV_S, 1);

    LOG_DBGFMT("[VAD] Secure partition initialized\r\n");

    while (1) {
        signals = psa_wait(PSA_WAIT_ANY, PSA_BLOCK);

        if (signals & TFM_AN552_VAD_SIGNAL) {
            vad_signal_handle(TFM_AN552_VAD_SIGNAL);
        } else {
            psa_panic();
        }
    }
}
