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

#include "i2c_sbcon_drv.h"

#define SDA  (1 << 1)
#define SCL  (1 << 0)
#define I2C_HIGH(i2c_dev, pin) (i2c_dev->ctrl_reg.set = pin)
#define I2C_LOW(i2c_dev, pin)  (i2c_dev->clear_reg = pin)
#define I2C_GET(i2c_dev, pin)  ((i2c_dev->ctrl_reg.status >> (pin-1)) & 0x01)

/* I2C SBCon state definitions */
#define I2C_SBCON_INITIALIZED  (1 << 0)

/* I2C SBCon register map structure */
struct i2c_sbcon_ctrl_t {
    union {
        /* Offset: 0x000 Control Status Register (r/ ) */
        volatile uint32_t status;
        /* Offset: 0x000 Control Set Register    ( /w) */
        volatile uint32_t set;
    } ctrl_reg;
    /* Offset: 0x004 Control Clear Register    ( /w) */
    volatile uint32_t clear_reg;
};

/*
 * \brief Transmits a data bit.
 *
 * \param[in] dev  Pointer to the I2C device \ref i2c_sbcon_dev_t
 * \param[in] bit  Bit to transmit.
 */
static void i2c_tx_bit(const struct i2c_sbcon_dev_t* dev,
                       uint8_t bit)
{
    struct i2c_sbcon_ctrl_t* p_i2c = (struct i2c_sbcon_ctrl_t*)dev->cfg->base;
    if (bit != 0) {
        I2C_HIGH(p_i2c, SDA);
    } else {
        I2C_LOW(p_i2c, SDA);
    }

    dev->cfg->sleep_us(dev->data->freq_us);

    I2C_HIGH(p_i2c, SCL);
    dev->cfg->sleep_us(dev->data->freq_us);

    I2C_LOW(p_i2c, SCL);
    dev->cfg->sleep_us(dev->data->freq_us);
}

/*
 * \brief Reads a data bit
 *
 * \param[in] dev  Pointer to the I2C device \ref i2c_sbcon_dev_t
 *
 * \returns Bit value received.
 */
static uint8_t i2c_rx_bit(const struct i2c_sbcon_dev_t* dev)
{
    uint8_t bit;
    struct i2c_sbcon_ctrl_t* p_i2c = (struct i2c_sbcon_ctrl_t*)dev->cfg->base;

    I2C_HIGH(p_i2c, SDA);
    dev->cfg->sleep_us(dev->data->freq_us);

    I2C_HIGH(p_i2c, SCL);
    dev->cfg->sleep_us(dev->data->freq_us);

    bit = I2C_GET(p_i2c, SDA);

    I2C_LOW(p_i2c, SCL);
    dev->cfg->sleep_us(dev->data->freq_us);

    return bit;
}

enum i2c_sbcon_error_t i2c_sbcon_init(struct i2c_sbcon_dev_t* dev,
                                              uint32_t sys_clk)
{
    if (sys_clk == 0) {
        return I2C_ERR_INVALID_ARG;
    }

    dev->data->sys_clk = sys_clk;

    dev->data->freq_us = (sys_clk / dev->cfg->default_freq_hz);

    dev->data->state = I2C_SBCON_INITIALIZED;

    return I2C_ERR_NONE;
}

enum i2c_sbcon_error_t i2c_sbcon_reset(struct i2c_sbcon_dev_t* dev)
{
    uint32_t iter;
    uint32_t freq_us = dev->data->freq_us;
    struct i2c_sbcon_ctrl_t* p_i2c = (struct i2c_sbcon_ctrl_t*)dev->cfg->base;

    if(!(dev->data->state & I2C_SBCON_INITIALIZED)) {
        return I2C_ERR_NOT_INIT;
    }

    /* The reset sequence is:
     *  - SDA line low
     *  - 9 clock pulses
     *  - SDA line high
     */
    I2C_LOW(p_i2c, SDA);
    dev->cfg->sleep_us(freq_us);

    for(iter=0; iter < 9; iter++) {
        I2C_LOW(p_i2c, SCL);
        dev->cfg->sleep_us(freq_us);
        I2C_HIGH(p_i2c, SCL);
        dev->cfg->sleep_us(freq_us);
    }

    I2C_HIGH(p_i2c, SDA);
    dev->cfg->sleep_us(freq_us);

    return I2C_ERR_NONE;
}

enum i2c_sbcon_error_t i2c_sbcon_set_freq(struct i2c_sbcon_dev_t* dev,
                                          uint32_t i2c_hz)
{
    if (dev->data->sys_clk < i2c_hz || i2c_hz == 0) {
        return I2C_ERR_INVALID_ARG;
    }

    if(!(dev->data->state & I2C_SBCON_INITIALIZED)) {
        return I2C_ERR_NOT_INIT;
    }

    dev->data->freq_us = (dev->data->sys_clk / i2c_hz);

    return I2C_ERR_NONE;
}

uint32_t i2c_sbcon_get_freq(struct i2c_sbcon_dev_t* dev)
{
    if(!(dev->data->state & I2C_SBCON_INITIALIZED)) {
        return 0;
    }

    return (dev->data->freq_us * dev->data->sys_clk);
}

enum i2c_sbcon_error_t i2c_sbcon_set_sys_clk( struct i2c_sbcon_dev_t* dev,
                                                uint32_t sys_clk)
{
    uint32_t i2c_hz;

    if (sys_clk == 0) {
        return I2C_ERR_INVALID_ARG;
    }

    if(!(dev->data->state & I2C_SBCON_INITIALIZED)) {
        return I2C_ERR_NOT_INIT;
    }

    /* Gets I2C frequency in Hz */
    i2c_hz = dev->data->freq_us * dev->data->sys_clk;

    /* Saves new system clock value */
    dev->data->sys_clk = sys_clk;

    /* Saves the I2C frequencu in us */
    dev->data->freq_us = (dev->data->sys_clk / i2c_hz);

    return I2C_ERR_NONE;
}

void i2c_sbcon_tx_start(const struct i2c_sbcon_dev_t* dev)
{
    struct i2c_sbcon_ctrl_t* p_i2c = (struct i2c_sbcon_ctrl_t*)dev->cfg->base;

    /* SDA goes from HIGH to LOW while SCL is HIGH */
    I2C_HIGH(p_i2c, (SCL | SDA));
    dev->cfg->sleep_us(dev->data->freq_us);

    I2C_LOW(p_i2c, SDA);
    dev->cfg->sleep_us(dev->data->freq_us);

    I2C_LOW(p_i2c, SCL);
    dev->cfg->sleep_us(dev->data->freq_us);
}

void i2c_sbcon_tx_stop(const struct i2c_sbcon_dev_t* dev)
{
    struct i2c_sbcon_ctrl_t* p_i2c = (struct i2c_sbcon_ctrl_t*)dev->cfg->base;

    /* SDA goes from LOW to HIGH while SCL is HIGH */
    I2C_LOW(p_i2c, SDA);
    dev->cfg->sleep_us(dev->data->freq_us);

    I2C_HIGH(p_i2c, SCL);
    dev->cfg->sleep_us(dev->data->freq_us);

    I2C_HIGH(p_i2c, SDA);
    dev->cfg->sleep_us(dev->data->freq_us);
}

void i2c_sbcon_tx_ack(const struct i2c_sbcon_dev_t* dev, uint8_t ack)
{
    i2c_tx_bit(dev, ack);
}

void i2c_sbcon_tx_byte(const struct i2c_sbcon_dev_t* dev, uint8_t data)
{
    uint8_t nbr_bits  ;

    for(nbr_bits=0; nbr_bits < 8; nbr_bits++) {
        i2c_tx_bit(dev, data & 0x80);
        data <<= 1;
    }
}

uint8_t i2c_sbcon_rx_ack(const struct i2c_sbcon_dev_t* dev)
{
    uint8_t ack;

    ack = i2c_rx_bit(dev);

    return ack;
}

uint8_t i2c_sbcon_rx_byte(struct i2c_sbcon_dev_t* dev)
{
    uint8_t numBits;
    uint8_t data = 0;

    for (numBits = 0; numBits < 8; numBits++) {
        data <<= 1;
        data |= i2c_rx_bit(dev);
    }

    return data;
}

enum i2c_sbcon_error_t i2c_sbcon_master_transmit(
                                                struct i2c_sbcon_dev_t* dev,
                                                uint16_t addr,
                                                const uint8_t* data,
                                                uint32_t len,
                                                uint8_t xfer_pending,
                                                uint32_t* nbr_bytes_write)
{
    i2c_sbcon_tx_start(dev);

    i2c_sbcon_tx_byte(dev, (uint8_t) addr);
    i2c_sbcon_rx_ack(dev);

    if(addr & I2C_10BIT) {
        i2c_sbcon_tx_byte(dev, (uint8_t)(addr >> 8));
        i2c_sbcon_rx_ack(dev);
    }

    for (*nbr_bytes_write = 0; *nbr_bytes_write < len; (*nbr_bytes_write)++) {
        i2c_sbcon_tx_byte(dev, data[*nbr_bytes_write]);
        i2c_sbcon_rx_ack(dev);
    }

    if (!xfer_pending) {
        i2c_sbcon_tx_stop(dev);
    }

    return I2C_ERR_NONE;
}

enum i2c_sbcon_error_t i2c_sbcon_master_receive(
                                              struct i2c_sbcon_dev_t* dev,
                                              uint16_t addr, uint8_t* data,
                                              uint32_t len,
                                              uint8_t xfer_pending,
                                              uint32_t* nbr_bytes_read)
{
    i2c_sbcon_tx_start(dev);

    i2c_sbcon_tx_byte(dev, (uint8_t) (addr | 0x1));
    i2c_sbcon_rx_ack(dev);

    if(addr & I2C_10BIT) {
        i2c_sbcon_tx_byte(dev, (uint8_t)(addr >> 8));
        i2c_sbcon_rx_ack(dev);
    }

    data[0] = i2c_sbcon_rx_byte(dev);
    for (*nbr_bytes_read = 1; *nbr_bytes_read < len; (*nbr_bytes_read)++) {
        i2c_sbcon_tx_ack(dev, 0);
        data[*nbr_bytes_read] = i2c_sbcon_rx_byte(dev);
    }
    i2c_sbcon_tx_ack(dev, 1);

    if (!xfer_pending) {
        i2c_sbcon_tx_stop(dev);
    }

    return I2C_ERR_NONE;
}
