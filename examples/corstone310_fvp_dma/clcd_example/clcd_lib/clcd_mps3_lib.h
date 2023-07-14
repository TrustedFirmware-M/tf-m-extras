/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

/**
 * \file clcd_mps3_lib.h
 * \brief Library functions for Color LCD.
 *      Features of CLCD MPS3 library:
 *          1. Initialize LCD
 *          2. Set window size and position
 *          3. Display image on LCD
 */

#ifndef __CLCD_MPS3_LIB_H__
#define __CLCD_MPS3_LIB_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "clcd_mps3_drv.h"


/**
 * \brief CLCD library error enumeration types
 */
enum clcd_mps3_lib_error_t{
    CLCD_MPS3_LIB_ERR_NONE = 0,          /*!< No error */
};

/**
 * \brief Initializes CLCD with maximum height and width and sets it to black
 *
 * \param[in] dev               MPS3 CLCD device where to write \ref clcd_mps3_dev_t
 *
 * \return Returns error code as specified in \ref clcd_mps3_lib_error_t
 */
enum clcd_mps3_lib_error_t clcd_mps3_init(struct clcd_mps3_dev_t* dev);

/**
 * \brief Display image on CLCD
 *
 * \param[in] dev               MPS3 CLCD device where to write \ref clcd_mps3_dev_t
 * \param[in] pos_horizontal    Horizontal position where to display image
 * \param[in] pos_vertical      Vertical position where to display image
 * \param[in] width             Width of image
 * \param[in] height            Height of image
 * \param[in] bitmap            Pointer to image data
 *
 * \return Returns error code as specified in \ref clcd_mps3_lib_error_t
 */
enum clcd_mps3_lib_error_t clcd_mps3_display_image(struct clcd_mps3_dev_t* dev,
                                                   uint32_t pos_horizontal,
                                                   uint32_t pos_vertical,
                                                   uint32_t width,
                                                   uint32_t height,
                                                   uint16_t *bitmap);

/**
 * \brief Set the window's dimensions
 *
 * The sent data will be displayed in this region.
 *
 * \param[in] dev               MPS3 CLCD device where to write \ref clcd_mps3_dev_t
 * \param[in] pos_horizontal    Horizontal position where to display image
 * \param[in] pos_vertical      Vertical position where to display image
 * \param[in] width             Width of image
 * \param[in] height            Height of image
 *
 * \return Returns error code as specified in \ref clcd_mps3_lib_error_t
 */
enum clcd_mps3_lib_error_t clcd_mps3_lib_set_window(struct clcd_mps3_dev_t* dev,
                                               uint32_t pos_horizontal,
                                               uint32_t pos_vertical,
                                               uint32_t width, uint32_t height);

#ifdef __cplusplus
}
#endif

#endif /* __CLCD_MPS3_LIB_H__ */
