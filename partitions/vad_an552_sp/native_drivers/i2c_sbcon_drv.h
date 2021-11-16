/*
 * Copyright (c) 2016-2018 ARM Limited
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

/**
 * \file i2c_sbcon_drv.h
 * \brief Generic driver for I2C SBCon.
 * The I2C SBCon IP requires a bit banging programing model.
 */

#ifndef __I2C_SBCON_DRV_H__
#define __I2C_SBCON_DRV_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define I2C_10BIT  0x0400

/**
 * \brief Sleeps for a given amount of microseconds.
 *
 * \param[in] us  Microseconds to sleep.
 */
typedef void SLEEP_US(uint32_t us);

/* I2C SBCon device configuration structure */
struct i2c_sbcon_dev_cfg_t {
    const uint32_t base;             /*!< I2C SBCon base address */
    const uint32_t default_freq_hz;  /*!< Operational frequence in Hz */
    SLEEP_US* const sleep_us;        /*!< Sleep function in us */
};

/* I2C SBCon device data structure */
struct i2c_sbcon_dev_data_t {
    uint32_t freq_us;  /*!< Operational frequence in us */
    uint32_t sys_clk;  /*!< System clock frequency */
    uint32_t state;    /*!< Indicates if the I2C SBCon driver
                            is initialized */
};

/* I2C SBCon device structure */
struct i2c_sbcon_dev_t {
    const struct i2c_sbcon_dev_cfg_t* const cfg;      /*!< I2C SBCon
                                                           configuration */
    struct i2c_sbcon_dev_data_t* const data;      /*!< I2C SBCon data */
};

/* Error codes returned by the driver functions */
enum i2c_sbcon_error_t {
    I2C_ERR_NONE,         /*!< No error */
    I2C_ERR_INVALID_ARG,  /*!< I2C invalid input arguments */
    I2C_ERR_NOT_INIT,     /*!< I2C not initialized */
};

/**
 * \brief Initializes I2C controller.
 *
 * \param[in] dev      I2C device struct \ref i2c_sbcon_dev_t
 * \param[in] sys_clk  System clock frequency.
 *
 * \return Returns error code as specified in \ref i2c_sbcon_error_t
 *
 * \note This function doesn't check if dev is NULL.
 */
enum i2c_sbcon_error_t i2c_sbcon_init(struct i2c_sbcon_dev_t* dev,
                                              uint32_t sys_clk);

/**
 * \brief Resets I2C controller.
 *
 * \param[in] dev  I2C device struct \ref i2c_sbcon_dev_t
 *
 * \return Returns error code as specified in \ref i2c_sbcon_error_t
 *
 * \note This function doesn't check if dev is NULL.
 */
enum i2c_sbcon_error_t i2c_sbcon_reset(struct i2c_sbcon_dev_t* dev);

/**
 * \brief Sets I2C speed.
 *
 * \param[in] dev     I2C device struct \ref i2c_sbcon_dev_t
 * \param[in] i2c_hz  I2C frequency in Hz.
 *
 * \return Returns error code as specified in \ref i2c_sbcon_error_t
 *
 * \note This function doesn't check if dev is NULL.
 */
enum i2c_sbcon_error_t i2c_sbcon_set_freq(
                                                struct i2c_sbcon_dev_t* dev,
                                                uint32_t i2c_hz);

/**
 * \brief Gets I2C speed.
 *
 * \param[in] dev  I2C device struct \ref i2c_sbcon_dev_t
 *
 * \return Returns I2C frequency in Hz.
 *
 * \note This function doesn't check if dev is NULL.
 */
uint32_t i2c_sbcon_get_freq(struct i2c_sbcon_dev_t* dev);

/**
 * \brief Sets system clock frequency.
 *
 * \param[in] dev      I2C device struct \ref i2c_sbcon_dev_t
 * \param[in] sys_clk  System clock frequency.
 *
 * \return Returns error code as specified in \ref i2c_sbcon_error_t
 *
 * \note This function doesn't check if dev is NULL.
 */
enum i2c_sbcon_error_t i2c_sbcon_set_sys_clk(
                                                struct i2c_sbcon_dev_t* dev,
                                                uint32_t sys_clk);

/*
 * \brief Transmits start bit.
 *
 * \param[in] dev  Pointer to the I2C device \ref i2c_sbcon_dev_t
 *
 * \note For better performance, this function doesn't check if the driver is
 *       initialized.
 */
void i2c_sbcon_tx_start(const struct i2c_sbcon_dev_t* dev);

/*
 * \brief Transmits stop bit.
 *
 * \param[in] dev  Pointer to the I2C device \ref i2c_sbcon_dev_t
 *
 * \note For better performance, this function doesn't check if the driver is
 *       initialized.
 */
void i2c_sbcon_tx_stop(const struct i2c_sbcon_dev_t* dev);

/*
 * \brief Writes acknowledge bit.
 *
 * \param[in] dev  Pointer to the I2C device \ref i2c_sbcon_dev_t
 * \param[in] ack  Ack bit to write.
 *
 * \note For better performance, this function doesn't check if the driver is
 *       initialized.
 */
void i2c_sbcon_tx_ack(const struct i2c_sbcon_dev_t* dev, uint8_t ack);

/*
 * \brief Transmits a byte.
 *
 * \param[in] dev   Pointer to the I2C device \ref i2c_sbcon_dev_t
 * \param[in] data  Byte to transmit.
 *
 * \note For better performance, this function doesn't check if the driver is
 *       initialized.
 */
void i2c_sbcon_tx_byte(const struct i2c_sbcon_dev_t* dev, uint8_t data);

/*
 * \brief Reads acknowledge bit
 *
 * \param[in] dev  Pointer to the I2C device \ref i2c_sbcon_dev_t
 *
 * \returns Bit value received.
 *
 * \note For better performance, this function doesn't check if the driver is
 *       initialized.
 */
uint8_t i2c_sbcon_rx_ack(const struct i2c_sbcon_dev_t* dev);

/*
 * \brief Reads a byte.
 *
 * \param[in] dev  Pointer to the I2C device \ref i2c_sbcon_dev_t
 *
 * \returns byte value received.
 *
 * \note For better performance, this function doesn't check if the driver is
 *       initialized.
 */
uint8_t i2c_sbcon_rx_byte(struct i2c_sbcon_dev_t* dev);

/**
 * \brief Writes data to I2C device.
 *
 * \param[in] dev               I2C device struct \ref i2c_sbcon_dev_t
 * \param[in] addr              I2C device address (7 bits or 10 bits).
 *                              The value can be ORed with I2C_10BIT to
 *                              identify a 10-bit address value.
 * \param[in] data              Buffer pointer to store the read data.
 * \param[in] len               Buffer length.
 * \param[in] xfer_pending      Transfer operation is pending, stop condition
 *                              will not be generated
 * \param[out] nbr_bytes_write  Number of bytes written
 *
 * \return Returns error code as specified in \ref i2c_sbcon_error_t
 *
 * \note For better performance, this function doesn't check if the pointers
 *       are NULL and if the driver is initialized.
 *       If it is on 7 bits, the addr argument has to be shifted by 1 bit to the
 *       left before being sent to the function. The least significant bit will
 *       be used to specify READ or WRITE.
 */
enum i2c_sbcon_error_t i2c_sbcon_master_transmit(
                                             struct i2c_sbcon_dev_t* dev,
                                             uint16_t addr, const uint8_t *data,
                                             uint32_t len, uint8_t xfer_pending,
                                             uint32_t* nbr_bytes_write);

/**
 * \brief Reads data from I2C device.
 *
 * \param[in]  dev             I2C device struct \ref i2c_sbcon_dev_t
 * \param[in]  addr            I2C device address (7 bits or 10 bits).
 *                             The value can be ORed with I2C_10BIT to
 *                             identify a 10-bit address value.
 * \param[out] data            Buffer pointer to store the read data.
 * \param[in]  len             Buffer length.
 * \param[in]  xfer_pending    Transfer operation is pending, stop condition
 *                             will not be generated
 * \param[out] nbr_bytes_read  Number of bytes read
 *
 * \return Returns error code as specified in \ref i2c_sbcon_error_t
 *
 * \note For better performance, this function doesn't check if the pointers
 *       are NULL and if the driver is initialized.
 *       If it is on 7 bits, the addr argument has to be shifted by 1 bit to the
 *       left before being sent to the function. The least significant bit will
 *       be used to specify READ or WRITE.
 */
enum i2c_sbcon_error_t i2c_sbcon_master_receive(
                                                struct i2c_sbcon_dev_t* dev,
                                                uint16_t addr, uint8_t *data,
                                                uint32_t len,
                                                uint8_t xfer_pending,
                                                uint32_t* nbr_bytes_read);

#ifdef __cplusplus
}
#endif
#endif /* __I2C_SBCON_DRV_H__ */
