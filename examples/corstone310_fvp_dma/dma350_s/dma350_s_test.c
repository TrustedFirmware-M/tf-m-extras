/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dma350_s_test.h"
#include "dma350_lib.h"
#include "platform_base_address.h"
#include "tfm_sp_log.h"

#include <string.h>

static int32_t dma350_native_drv_test(void);
static int32_t dma350_library_test(void);

#define DMA350_TEST_COPY_COUNT   442
static char DMA350_TEST_MEMORY_TO[DMA350_TEST_COPY_COUNT] = {0};
static char DMA350_TEST_MEMORY_FROM[DMA350_TEST_COPY_COUNT] = \
  "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vivamus ac lacinia"
  "sem. Donec a neque blandit, rhoncus quam efficitur, ultrices turpis. Maecen"
  "as ut pretium lorem. Sed urna augue, accumsan at porttitor sed, maximus vel"
  " sapien. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices p"
  "osuere cubilia curae; Vivamus porttitor viverra nisi, id dapibus risus ultr"
  "ices non. Phasellus in volutpat ex. Vivamus dictum aliquet gravida.";

#define DMA350_TEST_ENDIAN_ELEM_SIZE   3
#define DMA350_TEST_ENDIAN_ELEM_COUNT  3
#define DMA350_TEST_ENDIAN_LEN      \
                  (DMA350_TEST_ENDIAN_ELEM_SIZE * DMA350_TEST_ENDIAN_ELEM_COUNT)

static char DMA350_TEST_ENDIAN_FROM[DMA350_TEST_ENDIAN_LEN] =
    {'A','B','C','D','E','F','G','H','I'};
static char DMA350_TEST_ENDIAN_EXPECTED_RESULT[DMA350_TEST_ENDIAN_LEN] =
    {'C','B','A','F','E','D','I','H','G'};


const struct extra_tests_t plat_s_t = {
    .test_entry = dma350_s_test,
    .expected_ret = EXTRA_TEST_SUCCESS
};

static struct dma350_ch_dev_t DMA350_DMA0_CH0_DEV_S = {
    .cfg = {.ch_base = (DMACH_TypeDef *)(DMA_350_BASE_S + 0x1000UL),
            .channel = 0},
    .data = {0}};

int32_t dma350_s_test(void)
{
    int32_t result;
    enum dma350_ch_error_t ch_err;

    /* Init DMA channel */
    ch_err = dma350_ch_init(&DMA350_DMA0_CH0_DEV_S);
    if (ch_err != DMA350_CH_ERR_NONE) {
        tfm_sp_log_printf("DMA CH init failed: 0x%x\r\n", ch_err);
        return EXTRA_TEST_FAILED;
    }

    result = dma350_native_drv_test();
    if (result != EXTRA_TEST_SUCCESS) {
        return result;
    }

    result = dma350_library_test();
    if (result != EXTRA_TEST_SUCCESS) {
        return result;
    }

    return EXTRA_TEST_SUCCESS;
}

int32_t extra_tests_init(struct extra_tests_t *internal_test_t)
{
    return register_extra_tests(internal_test_t, &plat_s_t);
}

/**
 * \brief Test basic operation on a DMA-350 channel, using native drivers.
 *        Setup a basic copy operation, using byte-sized transactions.
 *
 * \returns Return EXTRA_TEST_SUCCESS if succeeds. Otherwise, return
 *          EXTRA_TEST_FAILED.
 */
static int32_t dma350_native_drv_test()
{
    union dma350_ch_status_t status;
    struct dma350_ch_dev_t *ch_dev = &DMA350_DMA0_CH0_DEV_S;

    /* Clear destination */
    memset(DMA350_TEST_MEMORY_TO, '.', DMA350_TEST_COPY_COUNT);

    /* Reset channel, wait for completion */
    dma350_ch_cmd(ch_dev, DMA350_CH_CMD_CLEARCMD);
    dma350_ch_wait_status(ch_dev);

    /* Configure channel */
    dma350_ch_set_src(ch_dev, (uint32_t)DMA350_TEST_MEMORY_FROM);
    dma350_ch_set_des(ch_dev, (uint32_t)DMA350_TEST_MEMORY_TO);
    dma350_ch_set_xsize32(ch_dev, DMA350_TEST_COPY_COUNT,
                            DMA350_TEST_COPY_COUNT);
    dma350_ch_set_transize(ch_dev, DMA350_CH_TRANSIZE_8BITS);
    dma350_ch_set_xtype(ch_dev, DMA350_CH_XTYPE_CONTINUE);
    dma350_ch_set_xaddr_inc(ch_dev, 1, 1);
    dma350_ch_set_src_trans_secure(ch_dev);
    dma350_ch_set_src_trans_privileged(ch_dev);
    dma350_ch_set_des_trans_secure(ch_dev);
    dma350_ch_set_des_trans_privileged(ch_dev);

    /* Execute channel */
    dma350_ch_cmd(ch_dev, DMA350_CH_CMD_ENABLECMD);

    /* Wait for completion, check if the operation is completed without error */
    status = dma350_ch_wait_status(ch_dev);
    if (!status.b.STAT_DONE || status.b.STAT_ERR) {
        tfm_sp_log_printf("Channel not finished properly\r\n");
        return EXTRA_TEST_FAILED;
    }

    /* Verify results */
    if (strncmp(DMA350_TEST_MEMORY_FROM, DMA350_TEST_MEMORY_TO,
                    DMA350_TEST_COPY_COUNT)) {
        tfm_sp_log_printf("Copied data mismatch\r\n");
        return EXTRA_TEST_FAILED;
    }

    return EXTRA_TEST_SUCCESS;
}

/**
 * \brief Test basic operation on a DMA-350 channel, using library functions.
 *        Use a string of characters to mimic multiple chunks of data. Use the
 *        endian swap library function to reverse the order of the characters
 *        within the chunks.
 *
 * \returns Return EXTRA_TEST_SUCCESS if succeeds. Otherwise, return
 *          EXTRA_TEST_FAILED.
 */
static int32_t dma350_library_test()
{
    enum dma350_lib_error_t status;
    struct dma350_ch_dev_t *ch_dev = &DMA350_DMA0_CH0_DEV_S;

    /* Clear destination */
    memset(DMA350_TEST_MEMORY_TO, '.', DMA350_TEST_ENDIAN_LEN);

    /* Call library function */
    status = dma350_endian_swap(ch_dev, DMA350_TEST_ENDIAN_FROM,
                    DMA350_TEST_MEMORY_TO, DMA350_TEST_ENDIAN_ELEM_SIZE,
                    DMA350_TEST_ENDIAN_ELEM_COUNT);

    /* Verify library return value */
    if (status != DMA350_LIB_ERR_NONE) {
        tfm_sp_log_printf("Library call failed with 0x%x\r\n", status);
        return EXTRA_TEST_FAILED;
    }

    /* Verify results */
    if (strncmp(DMA350_TEST_ENDIAN_EXPECTED_RESULT, DMA350_TEST_MEMORY_TO,
                    DMA350_TEST_ENDIAN_LEN)) {
        tfm_sp_log_printf("Copied data mismatch\r\n");
        return EXTRA_TEST_FAILED;
    }

    return EXTRA_TEST_SUCCESS;
}
