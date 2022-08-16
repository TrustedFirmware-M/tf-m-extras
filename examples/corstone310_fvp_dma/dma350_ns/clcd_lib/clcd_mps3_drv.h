/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

/**
 * \file clcd_mps3_drv.h
 * \brief Generic driver for Color LCD.
 *  Features of Color LCD driver:
 *      1. Write to command register
 *      2. Read from busy register
 *      3. Write/Read from data register
 *      4. Read/Clear access complete flag
 *      5. Enable/Disable write interrupt
 *      6. Read/Write miscellaneous control register
 *      7. Set blacklight off/on
 *      8. Set/Clear read enable signal bit
 *      9. Set/Clear reset bit
 *      10. Set/Clear register select bit
 *      11. Set/Clear write enable signal bit
 *      12. Set/Clear chip select signal bit
 */

#ifndef __CLCD_MPS3_DRV_H__
#define __CLCD_MPS3_DRV_H__

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Color LCD error enumeration types
 */
enum clcd_mps3_error_t{
    CLCD_MPS3_ERR_NONE = 0,          /*!< No error */
};

/**
 * \brief Color LCD device configuration structure
 */
struct clcd_mps3_dev_cfg_t{
    const uint32_t base;
    /*!< CLCD device base address */
};

/**
 * \brief Color CLCD device structure
 */
struct clcd_mps3_dev_t {
    const struct clcd_mps3_dev_cfg_t* const cfg;
    /*!< CLCD configuration structure */
};

/**
 * \brief Write to the LCD command register
 *
 * \param[in] dev      MPS3 CLCD device where to write \ref clcd_mps3_dev_t
 * \param[in] value    Value to write to the command register
 */
void clcd_mps3_write_command(struct clcd_mps3_dev_t* dev,
                             uint32_t value);

/**
 * \brief Read from the LCD busy register
 *
 * \param[in] dev MPS3 CLCD device where to read \ref clcd_mps3_dev_t
 *
 * \return Returns LCD busy register value
 */
uint32_t clcd_mps3_read_busy(struct clcd_mps3_dev_t* dev);

/**
 * \brief Write to the LCD data register
 *
 * \param[in] dev      MPS3 CLCD device where to write \ref clcd_mps3_dev_t
 * \param[in] value    Value to write to the data register
 */
void clcd_mps3_write_data(struct clcd_mps3_dev_t* dev,
                             uint32_t value);

/**
 * \brief Read from the LCD data register
 *
 * \param[in] dev MPS3 CLCD device where to read \ref clcd_mps3_dev_t
 *
 * \return Returns LCD data register value
 */
uint32_t clcd_mps3_read_data(struct clcd_mps3_dev_t* dev);

/**
 * \brief Read data from last request read
 *
 * \param[in] dev MPS3 CLCD device where to read \ref clcd_mps3_dev_t
 *
 * \return Returns data from last request read
 *
 * \note Access complete flag has to be set in order for the data to be valid
 */
uint8_t clcd_mps3_read_rd(struct clcd_mps3_dev_t* dev);

/**
 * \brief Clear access complete flag
 *
 * \param[in] dev MPS3 CLCD device where to write \ref clcd_mps3_dev_t
 */
void clcd_mps3_clear_access_complete(struct clcd_mps3_dev_t* dev);

/**
 * \brief Checks if access complete flag is set
 *
 * \param[in] dev MPS3 CLCD device where to read \ref clcd_mps3_dev_t
 *
 * \return Returns true if access complete flag is set, otherwise false
 */
bool clcd_mps3_is_access_complete_set(struct clcd_mps3_dev_t* dev);

/**
 * \brief Enable write interrupt
 *
 * \param[in] dev MPS3 CLCD device where to write \ref clcd_mps3_dev_t
 */
void clcd_mps3_enable_write_interrupt(struct clcd_mps3_dev_t* dev);

/**
 * \brief Disable write interrupt
 *
 * \param[in] dev MPS3 CLCD device where to write \ref clcd_mps3_dev_t
 */
void clcd_mps3_disable_write_interrupt(struct clcd_mps3_dev_t* dev);

/**
 * \brief Read state of Access Complete ANDed wih the write interrupt mask
 *
 * \param[in] dev MPS3 CLCD device where to write \ref clcd_mps3_dev_t
 *
 * \return Returns value of status
 */
uint32_t clcd_mps3_read_status(struct clcd_mps3_dev_t* dev);

/**
 * \brief Read Miscellaneous control register
 *
 * \param[in] dev MPS3 CLCD device where to read \ref clcd_mps3_dev_t
 *
 * \return Returns value of misc register
 */
uint32_t clcd_mps3_read_misc(struct clcd_mps3_dev_t* dev);

/**
 * \brief Write Miscellaneous control register
 *
 * \param[in] dev      MPS3 CLCD device where to write \ref clcd_mps3_dev_t
 * \param[in] value    Value to write to misc register
 */
void clcd_mps3_write_misc(struct clcd_mps3_dev_t* dev,
                             uint32_t value);

/**
 * \brief Set CLCD backlight on
 *
 * \param[in] dev MPS3 CLCD device where to write \ref clcd_mps3_dev_t
 */
void clcd_mps3_set_bl(struct clcd_mps3_dev_t* dev);

/**
 * \brief Set CLCD backlight off
 *
 * \param[in] dev MPS3 CLCD device where to write \ref clcd_mps3_dev_t
 */
void clcd_mps3_clear_bl(struct clcd_mps3_dev_t* dev);

/**
 * \brief Set CLCD Read enable signal
 *
 * \param[in] dev MPS3 CLCD device where to write \ref clcd_mps3_dev_t
 */
void clcd_mps3_set_rd(struct clcd_mps3_dev_t* dev);

/**
 * \brief Clear CLCD Read enable signal
 *
 * \param[in] dev MPS3 CLCD device where to write \ref clcd_mps3_dev_t
 */
void clcd_mps3_clear_rd(struct clcd_mps3_dev_t* dev);

/**
 * \brief Set CLCD Register select bit
 *
 * \param[in] dev MPS3 CLCD device where to write \ref clcd_mps3_dev_t
 */
void clcd_mps3_set_rs(struct clcd_mps3_dev_t* dev);

/**
 * \brief Clear CLCD Register select bit
 *
 * \param[in] dev MPS3 CLCD device where to write \ref clcd_mps3_dev_t
 */
void clcd_mps3_clear_rs(struct clcd_mps3_dev_t* dev);

/**
 * \brief Set CLCD reset
 *
 * \param[in] dev MPS3 CLCD device where to write \ref clcd_mps3_dev_t
 */
void clcd_mps3_set_reset(struct clcd_mps3_dev_t* dev);

/**
 * \brief Clear CLCD reset
 *
 * \param[in] dev MPS3 CLCD device where to write \ref clcd_mps3_dev_t
 */
void clcd_mps3_clear_reset(struct clcd_mps3_dev_t* dev);

/**
 * \brief Set CLCD Write enable signal
 *
 * \param[in] dev MPS3 CLCD device where to write \ref clcd_mps3_dev_t
 */
void clcd_mps3_set_wr(struct clcd_mps3_dev_t* dev);

/**
 * \brief Clear CLCD Write enable signal
 *
 * \param[in] dev MPS3 CLCD device where to write \ref clcd_mps3_dev_t
 */
void clcd_mps3_clear_wr(struct clcd_mps3_dev_t* dev);

/**
 * \brief Set CLCD Chip select signal
 *
 * \param[in] dev MPS3 CLCD device where to write \ref clcd_mps3_dev_t
 */
void clcd_mps3_set_cs(struct clcd_mps3_dev_t* dev);

/**
 * \brief Clear CLCD Chip select signal
 *
 * \param[in] dev MPS3 CLCD device where to write \ref clcd_mps3_dev_t
 */
void clcd_mps3_clear_cs(struct clcd_mps3_dev_t* dev);

#ifdef __cplusplus
}
#endif
#endif /* __CLCD_MPS3_DRV_H__ */
