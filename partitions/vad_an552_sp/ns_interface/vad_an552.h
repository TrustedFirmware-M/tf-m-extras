/*
 * Copyright (c) 2021-2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __VAD_API_H__
#define __VAD_API_H__

#include <stdint.h>

#include "psa/error.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \bried Status of the voice activity detection algorithm
 */
#define VAD_STOPPED             (0u)
#define VAD_NO_VOICE_DETECTED   (1u)
#define VAD_RECORDING           (2u)
#define VAD_VOICE_RECORDED      (3u)

/**
 * \brief Starts running voice activity detection algorithm on the microphone
 * input.
 *
 * Microphone samples are processed in interrupt context. If voice activity is
 * detected the partition starts recording a short sample.
 *
 * \return Returns values as specified by the \ref psa_status_t
 */
psa_status_t vad_an552_start_vad(void);

/**
 * \brief Queries the status of the voice activity detection algorithm.
 *
 * \param[out] vad_status   If no voice activity was detected since the
 *                          algorithm was started \ref VAD_VOICE_DETECTED is
 *                          given back, if the recording is running
 *                          \ref VAD_RECORDING, otherwise
 *                          \ref VAD_VOICE_RECORDED.
 *
 * \return Returns values as specified by the \ref psa_status_t
 */
psa_status_t vad_an552_query_vad(uint32_t *vad_status);

/**
 * \brief Returns the frequency of the recorded smaple.
 *
 * \param[out] freq         The frequency component with the most energy.
 *
 * \return Returns values as specified by the \ref psa_status_t
 */
psa_status_t vad_an552_get_freq(uint32_t *freq);

/**
 * \brief Stops the running voice activity detection algorithm.
 *
 * \return Returns values as specified by the \ref psa_status_t
 */
psa_status_t vad_an552_stop_vad(void);

#ifdef __cplusplus
}
#endif

#endif /* __VAD_API_H__ */
