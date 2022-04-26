/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef _MXIC_SPI_NOR_COMMAND_H
#define _MXIC_SPI_NOR_COMMAND_H

#include "Driver_SPI.h"

/**
 * \struct mxic_spi_nor_context_t
 *
 * \brief Structure holding SPI nor flash context.
 */
typedef struct {
    ARM_DRIVER_SPI *flash; /*!< The pointer to SPI driver */
    int32_t read_inst;     /*!< SPI nor flash read instruction */
    int32_t program_inst;  /*!< SPI nor flash program instruction */
    int32_t erase_inst;    /*!< SPI nor flash erase instruction */
    uint8_t addr_len;      /*!< SPI nor flash address length in bytes */
} mxic_spi_nor_context_t;

/**
 * \brief Initiate SPI nor flash context.
 *
 * \param[in] mxic_nor_ctx   Pointer to macronix SPI nor flash context pointer
 * \param[in] flash          Pointer to underlying SPI driver
 *
 * \return 0 if successful,
 *         -1 if failed
 */
int32_t mxic_spi_nor_init(mxic_spi_nor_context_t **mxic_nor_ctx,
                          ARM_DRIVER_SPI *flash);

/**
 * \brief Deinitiate SPI nor flash context.
 *
 * \param[in] mxic_nor_ctx   Pointer to macronix SPI nor flash context pointer
 *
 * \return 0 if successful,
 *         -1 if failed
 */
int32_t mxic_spi_nor_deinit(mxic_spi_nor_context_t **mxic_nor_ctx);

/**
 * \brief Send read packet command to secure Flash.
 *
 * \param[in]  mxic_nor_ctx  Pointer to macronix SPI nor flash context
 * \param[in]  command       Read packet command
 * \param[out] read_packet   Pointer to buffer holding packet read from
 *                           secure Flash
 * \param[in]  modifier      Command modifier:target address
 * \param[in]  packet_len    Read packet length
 *
 * \return 0 if successful,
 *         -1 if failed
 */
int32_t mxic_send_read_packet(mxic_spi_nor_context_t *mxic_nor_ctx,
                              uint8_t command, uint8_t *read_packet,
                              uint32_t modifier, uint32_t packet_len);

/**
 * \brief Send write packet command to secure Flash.
 *
 * \param[in] mxic_nor_ctx   Pointer to macronix SPI nor flash context
 * \param[in] command        Write packet command
 * \param[in] write_packet   Pointer to buffer holding packet to be send to
 *                           secure Flash
 * \param[in] modifier       Command modifier:target address
 * \param[in] packet_len     Write packet length
 *
 * \return 0 if successful,
 *         -1 if failed
 */
int32_t mxic_send_write_packet(mxic_spi_nor_context_t *mxic_nor_ctx,
                               uint8_t command, uint8_t *write_packet,
                               uint32_t modifier, uint32_t packet_len);

/**
 * \brief Read data from SPI nor flash.
 *
 * \param[in] mxic_nor_ctx   Pointer to macronix SPI nor flash context
 * \param[in] buffer         Pointer to buffer holding data read from SPI
 *                           nor flash
 * \param[in] addr           Target address
 * \param[in] size           Read data size in bytes
 *
 * \return 0 if successful,
 *         -1 if failed
 */
int32_t mxic_send_spi_nor_read(mxic_spi_nor_context_t *mxic_nor_ctx,
                               uint8_t *buffer, uint32_t addr, uint32_t size);

/**
 * \brief Program data to SPI nor flash.
 *
 * \param[in] mxic_nor_ctx   Pointer to macronix SPI nor flash context
 * \param[in] buffer         Pointer to buffer holding data to be programmed
 *                           to SPI nor flash
 * \param[in] addr           Target address
 * \param[in] size           Program data size in bytes
 *
 * \return 0 if successful,
 *         -1 if failed
 */
int32_t mxic_send_spi_nor_program(mxic_spi_nor_context_t *mxic_nor_ctx,
                                  uint8_t *buffer, uint32_t addr,
                                  uint32_t size);

/**
 * \brief Erase SPI nor flash sector/block.
 *
 * \param[in] mxic_nor_ctx   Pointer to macronix SPI nor flash context
 * \param[in] addr           Target sector/block address
 * \param[in] size           Erase size
 *
 * \return 0 if successful,
 *         -1 if failed
 */
int32_t mxic_send_spi_nor_erase(mxic_spi_nor_context_t *mxic_nor_ctx,
                                uint32_t addr, uint32_t size);

/**
 * \brief Read SPI nor flash ID.
 *
 * \param[in]  mxic_nor_ctx   Pointer to macronix SPI nor flash context
 * \param[out] id             Pointer to buffer holding flash ID
 * \param[in]  size           Flash ID size in bytes
 *
 * \return 0 if successful,
 *         -1 if failed
 */
int32_t mxic_send_spi_nor_rdid(mxic_spi_nor_context_t *mxic_nor_ctx,
                               uint8_t *id, uint8_t size);

/**
 * \brief Read the value of SPI nor flash status register.
 *
 * \param[in]  mxic_nor_ctx  Pointer to macronix SPI nor flash context
 * \param[out] sr            Pointer to buffer holding the status register value
 * \param[in]  size          The size of status register value in bytes
 *
 * \return 0 if successful,
 *         -1 if failed
 */
int32_t mxic_send_spi_nor_rdsr(mxic_spi_nor_context_t *mxic_nor_ctx,
                               uint8_t *sr, uint8_t size);

/**
 * \brief Read the value of SPI nor flash configuration register.
 *
 * \param[in]  mxic_nor_ctx  Pointer to macronix SPI nor flash context
 * \param[out] cr            Pointer to buffer holding configuration
 *                           register value
 * \param[in]  size          The size of configuration register value in bytes
 *
 * \return 0 if successful,
 *         -1 if failed
 */
int32_t mxic_send_spi_nor_rdcr(mxic_spi_nor_context_t *mxic_nor_ctx,
                               uint8_t *cr, uint8_t size);

/**
 * \brief Read the value of SPI nor flash security register.
 *
 * \param[in]  mxic_nor_ctx  Pointer to macronix SPI nor flash context
 * \param[out] scur          Pointer to buffer holding security register value
 * \param[in]  size          The size of security register value in bytes
 *
 * \return 0 if successful,
 *         -1 if failed
 */
int32_t mxic_send_spi_nor_rdscur(mxic_spi_nor_context_t *mxic_nor_ctx,
                                 uint8_t *scur, uint8_t size);

/**
 * \brief Set SPI nor flash Write Enable Latch(WEL) bit.
 *
 * \param[in] mxic_nor_ctx   Pointer to macronix SPI nor flash context
 *
 * \return 0 if successful,
 *         -1 if failed
 */
int32_t mxic_send_spi_nor_wren(mxic_spi_nor_context_t *mxic_nor_ctx);

/**
 * \brief SPI nor flash enter 4-byte mode.
 *
 * \param[in] mxic_nor_ctx   Pointer to macronix SPI nor flash context
 *
 * \return 0 if successful,
 *         -1 if failed
 */
int32_t mxic_send_spi_nor_en4b(mxic_spi_nor_context_t *mxic_nor_ctx);

/**
 * \brief SPI nor flash enter security field.
 *
 * \param[in] mxic_nor_ctx   Pointer to macronix SPI nor flash context
 *
 * \return 0 if successful,
 *         -1 if failed
 */
int32_t mxic_send_spi_nor_ensf(mxic_spi_nor_context_t *mxic_nor_ctx);

/**
 * \brief SPI nor flash exist security field.
 *
 * \param[in] mxic_nor_ctx   Pointer to macronix SPI nor flash context
 *
 * \return 0 if successful,
 *         -1 if failed
 */
int32_t mxic_send_spi_nor_exsf(mxic_spi_nor_context_t *mxic_nor_ctx);

/**
 * \brief Enable SPI nor flash reset command.
 *
 * \param[in] mxic_nor_ctx   Pointer to macronix SPI nor flash context
 *
 * \return 0 if successful,
 *         -1 if failed
 */
int32_t mxic_send_spi_nor_rsten(mxic_spi_nor_context_t *mxic_nor_ctx);

/**
 * \brief SPI nor flash system(software) reset.
 *
 * \param[in] mxic_nor_ctx   Pointer to macronix SPI nor flash context
 *
 * \return 0 if successful,
 *         -1 if failed
 */
int32_t mxic_send_spi_nor_rst(mxic_spi_nor_context_t *mxic_nor_ctx);

#endif /* _MXIC_SPI_NOR_COMMAND_H */
