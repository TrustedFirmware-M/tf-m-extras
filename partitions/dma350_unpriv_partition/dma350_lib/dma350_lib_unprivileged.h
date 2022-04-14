/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

/**
 * \file dma350_lib_unprivileged.h
 *
 * \brief Library functions for DMA350 Direct Access Memory
 *      Functions:
 *          1. Memory copy from non-privileged mode
 *          2. Memory move from non-privileged mode
 */

#ifndef __DMA350_LIB_UNPRIVILEGED_H__
#define __DMA350_LIB_UNPRIVILEGED_H__

#include "dma350_lib.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Clear a status bit of the dma channel
 *
 * \param[in] channel    DMA350 channel number
 *
 * \return Result of the operation \ref dma350_lib_error_t
 *
 * \note This function can be called from non-privileged level.
 */
enum dma350_lib_error_t dma350_clear_done_irq_unpriv(uint8_t channel);

/**
 * \brief Copy a specified number of bytes from one memory to another
 *
 * \param[in] channel    DMA350 channel number
 * \param[in] src        Source address, where to copy from
 * \param[in] des        Destination address, where to copy to
 * \param[in] size       Number of bytes to copy
 * \param[in] exec_type  Execution type \ref dma350_lib_exec_type_t
 *
 * \return Result of the operation \ref dma350_lib_error_t
 *
 * \note This function can be called from non-privileged level.
 */
enum dma350_lib_error_t dma350_memcpy_unpriv(uint8_t channel, void* src,
                                        void* des, uint32_t size,
                                        enum dma350_lib_exec_type_t exec_type);

/**
 * \brief Copy a specified number of bytes from one memory to another
 *        or overlap on same memory.
 *
 * \param[in] channel    DMA350 channel number
 * \param[in] src        Source address, where to move from
 * \param[in] des        Destination address, where to move to
 * \param[in] size       Number of bytes to move
 * \param[in] exec_type  Execution type \ref dma350_lib_exec_type_t
 *
 * \return Result of the operation \ref dma350_lib_error_t
 *
 * \note This function can be called from non-privileged level.
 */
enum dma350_lib_error_t dma350_memmove_unpriv(uint8_t channel, void* src,
                                        void* des, uint32_t size,
                                        enum dma350_lib_exec_type_t exec_type);


/**
 * \brief Get the status of the dma channel
 *
 * \param[in] channel    DMA350 channel number
 * \param[out] status    DMA350 channel status
 *
 * \return Result of the operation \ref dma350_lib_error_t
 *
 * \note This function can be called from non-privileged level.
 */
enum dma350_lib_error_t dma350_ch_get_status_unpriv(uint8_t channel,
                                        union dma350_ch_status_t *status);

#ifdef __cplusplus
}
#endif
#endif /*__DMA350_LIB_UNPRIVILEGED_H__ */
