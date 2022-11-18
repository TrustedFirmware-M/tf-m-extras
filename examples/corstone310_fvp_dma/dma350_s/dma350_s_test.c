/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 * Copyright (c) 2022 Cypress Semiconductor Corporation (an Infineon company)
 * or an affiliate of Cypress Semiconductor Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "extra_s_tests.h"
#include "dma350_lib.h"
#include "platform_base_address.h"
#include "tfm_sp_log.h"

#include <string.h>

static void dma350_native_drv_test(struct test_result_t *ret);
static void dma350_library_test(struct test_result_t *ret);

/* TODO: if needed each test function can be made as a separate test case, in
 * such case EXTRA_TEST_XX definitions can be removed */
#define EXTRA_TEST_SUCCESS 0
#define EXTRA_TEST_FAILED -1

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


static struct dma350_ch_dev_t DMA350_DMA0_CH0_DEV_S = {
    .cfg = {.ch_base = (DMACH_TypeDef *)(DMA_350_BASE_S + 0x1000UL),
            .channel = 0},
    .data = {0}};

static struct test_t plat_s_t[] = {
    {&dma350_native_drv_test, "TFM_S_EXTRA_TEST_1001",
     "DMA350 Native driver"},
    {&dma350_library_test, "TFM_S_EXTRA_TEST_1002",
     "DMA350 Library"},
};

void register_testsuite_extra_s_interface(struct test_suite_t *p_test_suite)
{
    uint32_t list_size;

    list_size = (sizeof(plat_s_t) /
                 sizeof(plat_s_t[0]));

    set_testsuite("Extra Secure interface tests"
                  "(TFM_S_EXTRA_TEST_1XXX)",
                  plat_s_t, list_size, p_test_suite);
}

/**
 * \brief Test basic operation on a DMA-350 channel, using native drivers.
 *        Setup a basic copy operation, using byte-sized transactions.
 *
 * \returns Return EXTRA_TEST_SUCCESS if succeeds. Otherwise, return
 *          EXTRA_TEST_FAILED.
 */
static void dma350_native_drv_test(struct test_result_t *ret)
{
    union dma350_ch_status_t status;
    struct dma350_ch_dev_t *ch_dev = &DMA350_DMA0_CH0_DEV_S;
    enum dma350_ch_error_t ch_err;

    /* Init DMA channel */
    ch_err = dma350_ch_init(&DMA350_DMA0_CH0_DEV_S);
    if (ch_err != DMA350_CH_ERR_NONE) {
        printf("DMA CH init failed: 0x%x\r\n", ch_err);
        ret->val = TEST_FAILED;
        return;
    }

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
        printf("Channel not finished properly\r\n");
        ret->val = TEST_FAILED;
        return;
    }

    /* Verify results */
    if (strncmp(DMA350_TEST_MEMORY_FROM, DMA350_TEST_MEMORY_TO,
                    DMA350_TEST_COPY_COUNT)) {
        printf("Copied data mismatch\r\n");
        ret->val = TEST_FAILED;
        return;
    }
    ret->val = TEST_PASSED;
    return;
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
static void dma350_library_test(struct test_result_t *ret)
{
    enum dma350_lib_error_t status;
    struct dma350_ch_dev_t *ch_dev = &DMA350_DMA0_CH0_DEV_S;
    enum dma350_ch_error_t ch_err;

    /* Init DMA channel */
    ch_err = dma350_ch_init(&DMA350_DMA0_CH0_DEV_S);
    if (ch_err != DMA350_CH_ERR_NONE) {
        printf("DMA CH init failed: 0x%x\r\n", ch_err);
        ret->val = TEST_FAILED;
        return;
    }

    /* Clear destination */
    memset(DMA350_TEST_MEMORY_TO, '.', DMA350_TEST_ENDIAN_LEN);

    /* Call library function */
    status = dma350_endian_swap(ch_dev, DMA350_TEST_ENDIAN_FROM,
                    DMA350_TEST_MEMORY_TO, DMA350_TEST_ENDIAN_ELEM_SIZE,
                    DMA350_TEST_ENDIAN_ELEM_COUNT);

    /* Verify library return value */
    if (status != DMA350_LIB_ERR_NONE) {
        printf("Library call failed with 0x%x\r\n", status);
        ret->val = TEST_FAILED;
        return;
    }

    /* Verify results */
    if (strncmp(DMA350_TEST_ENDIAN_EXPECTED_RESULT, DMA350_TEST_MEMORY_TO,
                    DMA350_TEST_ENDIAN_LEN)) {
        printf("Copied data mismatch:\r\nEXP: %s\r\nDES: %s\r\n",
                    DMA350_TEST_ENDIAN_EXPECTED_RESULT,
                    DMA350_TEST_MEMORY_TO);
        ret->val = TEST_FAILED;
        return;
    }

    ret->val = TEST_PASSED;
    return;
}
