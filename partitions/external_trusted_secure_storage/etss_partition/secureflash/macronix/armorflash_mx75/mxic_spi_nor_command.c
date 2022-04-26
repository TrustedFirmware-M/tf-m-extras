/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <stdint.h>
#include <string.h>
#include "mxic_spi_nor_command.h"
#include "Driver_SPI.h"
#include "tfm_memory_utils.h"

#define STD_INST_PP              0x02
#define STD_INST_READ            0x03
#define STD_INST_ERASE_4K        0x20
#define STD_INST_PP_4B           0x12
#define STD_INST_READ_4B         0x13
#define STD_INST_ERASE_4K_4B     0x21
#define STD_INST_RDSCUR          0x2B
#define STD_INST_RDCR            0x15
#define STD_INST_RDSR            0x05
#define STD_INST_RDID            0x9F
#define STD_INST_RSTEN           0x66
#define STD_INST_RST             0x99
#define STD_INST_WREN            0x06
#define STD_INST_FREAD           0x0B
#define STD_INST_ENSF            0xB2
#define STD_INST_EXSF            0xC2
#define STD_INST_EN4B            0xB7

#define SIZE_128M_BITS           (1 << 24)

#define ADDRESS_LEN_3B           3
#define ADDRESS_LEN_4B           4

#define DUMMY_VALUE              0xFF
#define CMD_PACKET_BUF_SIZE      (128)

static mxic_spi_nor_context_t mxic_spi_nor_context = {};

static int32_t _send_spi_nor_rx_command(mxic_spi_nor_context_t *mxic_nor_ctx,
                                        int32_t inst, uint32_t addr,
                                        uint8_t addr_len, uint8_t dummy_len,
                                        uint8_t *const rx_buf, uint32_t rx_len);
static int32_t _send_spi_nor_tx_command(mxic_spi_nor_context_t *mxic_nor_ctx,
                                        int32_t inst,
                                        uint32_t addr, uint8_t addr_len,
                                        const uint8_t *tx_buf, uint32_t tx_len);
static int32_t _sw_reset(mxic_spi_nor_context_t *mxic_nor_ctx);
static int32_t _check_en4b(mxic_spi_nor_context_t *mxic_nor_ctx);

int32_t mxic_spi_nor_init(mxic_spi_nor_context_t **mxic_nor_ctx,
                          ARM_DRIVER_SPI *flash)
{
    *mxic_nor_ctx = &mxic_spi_nor_context;
    tfm_memset(*mxic_nor_ctx, 0x00, sizeof(mxic_spi_nor_context_t));
    (*mxic_nor_ctx)->flash = (ARM_DRIVER_SPI *)flash;
    (*mxic_nor_ctx)->addr_len = ADDRESS_LEN_3B;
    (*mxic_nor_ctx)->read_inst = STD_INST_READ;
    (*mxic_nor_ctx)->program_inst = STD_INST_PP;
    (*mxic_nor_ctx)->erase_inst = STD_INST_ERASE_4K;
    if (0 != flash->Initialize(NULL)) {
        goto exit_point_init;
    }
    if (0 != _sw_reset(*mxic_nor_ctx)) {
        goto exit_point_init;
    }
    if (0 != _check_en4b(*mxic_nor_ctx)) {
        goto exit_point_init;
    }
    return 0;
exit_point_init:
    mxic_spi_nor_deinit(mxic_nor_ctx);
    return -1;
}

int32_t mxic_spi_nor_deinit(mxic_spi_nor_context_t **mxic_nor_ctx)
{
    if (0 != *mxic_nor_ctx) {
        *mxic_nor_ctx = 0;
    }
    return 0;
}

int32_t mxic_send_read_packet(mxic_spi_nor_context_t *mxic_nor_ctx,
                              uint8_t command, uint8_t *read_packet,
                              uint32_t modifier, uint32_t packet_len)
{
    return _send_spi_nor_rx_command(mxic_nor_ctx, command, modifier,
                                    mxic_nor_ctx->addr_len, 0,
                                    read_packet, packet_len);
}

int32_t mxic_send_write_packet(mxic_spi_nor_context_t *mxic_nor_ctx,
                               uint8_t command, uint8_t *write_packet,
                               uint32_t modifier, uint32_t packet_len)
{
    return _send_spi_nor_tx_command(mxic_nor_ctx, command,
                                    modifier, mxic_nor_ctx->addr_len,
                                    write_packet, packet_len);
}

int32_t mxic_send_spi_nor_read(mxic_spi_nor_context_t *mxic_nor_ctx,
                               uint8_t *buffer, uint32_t addr, uint32_t size)
{
    return _send_spi_nor_rx_command(mxic_nor_ctx, mxic_nor_ctx->read_inst,
                                    addr, mxic_nor_ctx->addr_len, 0,
                                    buffer, size);
}

int32_t mxic_send_spi_nor_program(mxic_spi_nor_context_t *mxic_nor_ctx,
                                  uint8_t *buffer, uint32_t addr, uint32_t size)
{
    return _send_spi_nor_tx_command(mxic_nor_ctx, mxic_nor_ctx->program_inst,
                                    addr, mxic_nor_ctx->addr_len, buffer, size);
}

int32_t mxic_send_spi_nor_erase(mxic_spi_nor_context_t *mxic_nor_ctx,
                                uint32_t addr, uint32_t size)
{
    return _send_spi_nor_tx_command(mxic_nor_ctx, mxic_nor_ctx->erase_inst,
                                    addr, mxic_nor_ctx->addr_len, NULL, size);
}

int32_t mxic_send_spi_nor_rdid(mxic_spi_nor_context_t *mxic_nor_ctx,
                               uint8_t *id, uint8_t size)
{
    return _send_spi_nor_rx_command(mxic_nor_ctx, STD_INST_RDID, 0, 0, 0,
                                    id, size);
}

int32_t mxic_send_spi_nor_rdsr(mxic_spi_nor_context_t *mxic_nor_ctx,
                               uint8_t *sr, uint8_t size)
{
    return _send_spi_nor_rx_command(mxic_nor_ctx, STD_INST_RDSR, 0, 0, 0,
                                    sr, size);
}

int32_t mxic_send_spi_nor_rdcr(mxic_spi_nor_context_t *mxic_nor_ctx,
                               uint8_t *cr, uint8_t size)
{
    return _send_spi_nor_rx_command(mxic_nor_ctx, STD_INST_RDCR, 0, 0, 0,
                                    cr, size);
}

int32_t mxic_send_spi_nor_rdscur(mxic_spi_nor_context_t *mxic_nor_ctx,
                                 uint8_t *scur, uint8_t size)
{
    return _send_spi_nor_rx_command(mxic_nor_ctx, STD_INST_RDSCUR, 0, 0, 0,
                                    scur, size);
}

int32_t mxic_send_spi_nor_wren(mxic_spi_nor_context_t *mxic_nor_ctx)
{
    return _send_spi_nor_tx_command(mxic_nor_ctx, STD_INST_WREN, 0, 0, NULL, 0);
}

int32_t mxic_send_spi_nor_en4b(mxic_spi_nor_context_t *mxic_nor_ctx)
{
    return _send_spi_nor_tx_command(mxic_nor_ctx, STD_INST_EN4B, 0, 0, NULL, 0);
}

int32_t mxic_send_spi_nor_ensf(mxic_spi_nor_context_t *mxic_nor_ctx)
{
    return _send_spi_nor_tx_command(mxic_nor_ctx, STD_INST_ENSF, 0, 0, NULL, 0);
}

int32_t mxic_send_spi_nor_exsf(mxic_spi_nor_context_t *mxic_nor_ctx)
{
    return _send_spi_nor_tx_command(mxic_nor_ctx, STD_INST_EXSF, 0, 0, NULL, 0);
}

int32_t mxic_send_spi_nor_rsten(mxic_spi_nor_context_t *mxic_nor_ctx)
{
    return _send_spi_nor_tx_command(mxic_nor_ctx, STD_INST_RSTEN, 0, 0, NULL, 0);
}

int32_t mxic_send_spi_nor_rst(mxic_spi_nor_context_t *mxic_nor_ctx)
{
    return _send_spi_nor_tx_command(mxic_nor_ctx, STD_INST_RST, 0, 0, NULL, 0);
}

static int32_t _send_spi_nor_rx_command(mxic_spi_nor_context_t *mxic_nor_ctx,
                                        int32_t inst, uint32_t addr,
                                        uint8_t addr_len, uint8_t dummy_len,
                                        uint8_t *rx_buf, uint32_t rx_len)
{
    int32_t addr_shift, cmd_len;
    uint8_t cmd_buf[CMD_PACKET_BUF_SIZE];

    mxic_nor_ctx->flash->Control(ARM_SPI_CONTROL_SS, ARM_SPI_SS_ACTIVE);
    // instruction
    /* Fixme: support one-byte instruction only*/
    cmd_buf[0] = (uint8_t)inst;
    cmd_len = 1;
    // address
    if (addr_len) {
        for (addr_shift = ((addr_len - 1) * 8); addr_shift >= 0;
             addr_shift -= 8, cmd_len++) {
            cmd_buf[cmd_len] = (addr >> addr_shift) & 0xFF;
        }
    }
    //dummy bytes
    for (uint8_t i = 0; i < dummy_len; i++, cmd_len++) {
        cmd_buf[cmd_len] = DUMMY_VALUE;
    }
    mxic_nor_ctx->flash->Send(cmd_buf, cmd_len);
    // read data
    mxic_nor_ctx->flash->Receive(rx_buf, (int32_t)rx_len);
    mxic_nor_ctx->flash->Control(ARM_SPI_CONTROL_SS, ARM_SPI_SS_INACTIVE);
    return 0;
}

static int32_t _send_spi_nor_tx_command(mxic_spi_nor_context_t *mxic_nor_ctx,
                                        int32_t inst,
                                        uint32_t addr,uint8_t addr_len,
                                        const uint8_t *tx_buf, uint32_t tx_len)
{
    int32_t addr_shift, cmd_len;
    uint8_t cmd_buf[CMD_PACKET_BUF_SIZE];

    mxic_nor_ctx->flash->Control(ARM_SPI_CONTROL_SS, ARM_SPI_SS_ACTIVE);
    // instruction
    /* Fixme: support one-byte instruction only */
    cmd_buf[0] = (uint8_t)inst;
    cmd_len = 1;
    // address
    if (addr_len) {
        for (addr_shift = ((addr_len - 1) * 8); addr_shift >= 0;
             addr_shift -= 8, cmd_len++) {
            cmd_buf[cmd_len] = (addr >> addr_shift) & 0xFF;
        }
    }
    // write data
    tfm_memcpy(cmd_buf + cmd_len, tx_buf, tx_len);
    cmd_len += tx_len;
    mxic_nor_ctx->flash->Send(cmd_buf, cmd_len);
    mxic_nor_ctx->flash->Control(ARM_SPI_CONTROL_SS, ARM_SPI_SS_INACTIVE);
    return 0;
}

static int32_t _sw_reset(mxic_spi_nor_context_t *mxic_nor_ctx)
{
    if (0 != mxic_send_spi_nor_rsten(mxic_nor_ctx)) {
        return -1;
    }
    if (0 != mxic_send_spi_nor_rst(mxic_nor_ctx)) {
        return -1;
    }
    return 0;
}

static int32_t _check_en4b(mxic_spi_nor_context_t *mxic_nor_ctx)
{
    uint64_t density;
    uint8_t id[3] ={}, cr;

    if (0 != mxic_send_spi_nor_rdid(mxic_nor_ctx, id, 3)) {
        return -1;
    }
    density = 1llu << (id[2] & 0x3F);
    if (SIZE_128M_BITS < density) {
        if (0 != mxic_send_spi_nor_en4b(mxic_nor_ctx)) {
            return -1;
        }
        if (0 != mxic_send_spi_nor_rdcr(mxic_nor_ctx, &cr, 1)) {
            return -1;
        }
        if (cr & (1<<5)) {
            mxic_nor_ctx->addr_len = ADDRESS_LEN_4B;
            return 0;
        } else {
            return -1;
        }
    }
    return 0;
}
