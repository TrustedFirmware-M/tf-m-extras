/*
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "psa/service.h"
#include "psa_manifest/tfm_dma350_example_partition.h"
#include "tfm_log_unpriv.h"

#include "dma350_privileged_config.h"
#include "dma350_lib.h"
#include "dma350_lib_unprivileged.h"

/* For privileged section */
#include "region.h"
REGION_DECLARE(Image$$, ER_TFM_DATA, $$Base);

#define DMA350_TEST_COPY_COUNT  10
static char DMA350_TEST_MEMORY_TO[DMA350_TEST_COPY_COUNT];
static char DMA350_TEST_MEMORY_FROM[DMA350_TEST_COPY_COUNT] = "Copy Test";

static bool test_wrong_channel(void)
{
    enum dma350_lib_error_t status;
    union dma350_ch_status_t ch_status;

    INFO_UNPRIV_RAW("[DMA-350 Partition] Wrong channel test\n");

    /* Channel 22 is not a valid channel number */
    status = dma350_ch_get_status_unpriv(22, &ch_status);
    if (status != DMA350_LIB_ERR_CHANNEL_INVALID) {
        INFO_UNPRIV_RAW("[DMA-350 Partition] Unexpected dma350_ch_get_status_unpriv return value (%d), expected: %d\n",
                   status, DMA350_LIB_ERR_CHANNEL_INVALID);
        return true;
    }

    /* Channel 1 is not accessable by unprivileged */
    status = dma350_ch_get_status_unpriv(1, &ch_status);
    if (status != DMA350_LIB_ERR_RANGE_NOT_ACCESSIBLE) {
        INFO_UNPRIV_RAW("[DMA-350 Partition] Unexpected dma350_ch_get_status_unpriv return value (%d), expected: %d\n",
                   status, DMA350_LIB_ERR_RANGE_NOT_ACCESSIBLE);
        return true;
    }

    INFO_UNPRIV_RAW("[DMA-350 Partition] Test success!\r\n\n");
    return false;
}

static bool test_memcopy_blocking(void)
{
    enum dma350_lib_error_t status;

    INFO_UNPRIV_RAW("[DMA-350 Partition] Blocking memcopy test\n");

    /* Blocking unprivileged usage of the DMA in our reference solution is
     * prohibited, as the request is processed within an SVC handler context */
    status = dma350_memcpy_unpriv(0, (void *)DMA350_TEST_MEMORY_FROM,
                                     (void *)DMA350_TEST_MEMORY_TO,
                                     DMA350_TEST_COPY_COUNT,
                                     DMA350_LIB_EXEC_BLOCKING);

    if (status != DMA350_LIB_ERR_CFG_ERR) {
        INFO_UNPRIV_RAW("[DMA-350 Partition] Unexpected dma350_memcpy_unpriv return value (%d), expected: %d\n",
                   status, DMA350_LIB_ERR_CFG_ERR);
        return true;
    }

    INFO_UNPRIV_RAW("[DMA-350 Partition] Test success!\r\n\n");
    return false;
}

static bool test_memcopy_non_blocking_priv_address(void)
{
    enum dma350_lib_error_t status;

    INFO_UNPRIV_RAW("[DMA-350 Partition] Non-blocking memcopy with privileged address test\n");

    /* Access for privileged memory should be rejected. */
    status = dma350_memcpy_unpriv(0, (void *)&REGION_NAME(Image$$, ER_TFM_DATA, $$Base),
                                     (void *)DMA350_TEST_MEMORY_TO,
                                     DMA350_TEST_COPY_COUNT,
                                     DMA350_LIB_EXEC_IRQ);

    if (status != DMA350_LIB_ERR_RANGE_NOT_ACCESSIBLE) {
        INFO_UNPRIV_RAW("[DMA-350 Partition] Unexpected dma350_memcpy_unpriv return value (%d), expected: %d\n",
                   status, DMA350_LIB_ERR_RANGE_NOT_ACCESSIBLE);
        return true;
    }

    INFO_UNPRIV_RAW("[DMA-350 Partition] Test success!\r\n\n");
    return false;
}

static bool test_memcopy_non_blocking(void)
{
    enum dma350_lib_error_t status;
    union dma350_ch_status_t ch_status;

    INFO_UNPRIV_RAW("[DMA-350 Partition] Non-blocking memcopy test\n");

    /* Clear destination */
    memset(DMA350_TEST_MEMORY_TO, '.', DMA350_TEST_COPY_COUNT);

    psa_irq_enable(TFM_DMA0_CH0_IRQ_SIGNAL);

    status = dma350_memcpy_unpriv(0, (void *)DMA350_TEST_MEMORY_FROM,
                                     (void *)DMA350_TEST_MEMORY_TO,
                                     DMA350_TEST_COPY_COUNT,
                                     DMA350_LIB_EXEC_IRQ);

    if (status != DMA350_LIB_ERR_NONE) {
        INFO_UNPRIV_RAW("[DMA-350 Partition] Memcpy failed (%d)\n", status);
        psa_irq_disable(TFM_DMA0_CH0_IRQ_SIGNAL);
        return true;
    } else {
        INFO_UNPRIV_RAW("[DMA-350 Partition] Waiting for DMA0 CH0 interrupt..\n");
        if (psa_wait(TFM_DMA0_CH0_IRQ_SIGNAL, PSA_BLOCK) != TFM_DMA0_CH0_IRQ_SIGNAL) {
            psa_panic();
        }
        INFO_UNPRIV_RAW("[DMA-350 Partition] DMA0 CH0 interrupt received.\n");

        /* Check if the operation is completed without error */
        status = dma350_ch_get_status_unpriv(0, &ch_status);
        if (status != DMA350_LIB_ERR_NONE) {
            INFO_UNPRIV_RAW("[DMA-350 Partition] Couldn't get status (%d)\n",
                       status);
            return true;
        }
        if (!ch_status.b.STAT_DONE || ch_status.b.STAT_ERR) {
            INFO_UNPRIV_RAW("[DMA-350 Partition] Channel not finished properly. Status: 0x%x\n",
                       ch_status.w);
            return true;
        }

        /* Clear channel irq */
        status = dma350_clear_done_irq_unpriv(0);
        if (status != DMA350_LIB_ERR_NONE) {
            INFO_UNPRIV_RAW("[DMA-350 Partition] Couldn't clear irq (%d)\n",
                       status);
            return true;
        }

        psa_irq_disable(TFM_DMA0_CH0_IRQ_SIGNAL);
        psa_eoi(TFM_DMA0_CH0_IRQ_SIGNAL);

        /* Verify results */
        if (strncmp(DMA350_TEST_MEMORY_FROM, DMA350_TEST_MEMORY_TO,
                        DMA350_TEST_COPY_COUNT)) {
            INFO_UNPRIV_RAW("[DMA-350 Partition] Copied data mismatch\n");
            return true;
        }
    }

    INFO_UNPRIV_RAW("[DMA-350 Partition] Test success!\r\n\n");
    return false;
}


/**
 * \brief The DMA-350 example partition's entry function.
 */
void tfm_dma350_example_partition_main(void)
{
    bool failed = false;

    if(test_wrong_channel()) {
        ERROR_UNPRIV_RAW("[DMA-350 Partition] Wrong channel test failed\n");
        failed = true;
    }
    if(test_memcopy_blocking()) {
        ERROR_UNPRIV_RAW("[DMA-350 Partition] Blocking memcopy test failed\n");
        failed = true;
    }
    if(test_memcopy_non_blocking_priv_address()) {
        ERROR_UNPRIV_RAW("[DMA-350 Partition] Non-blocking memcopy with privileged address test failed\n");
        failed = true;
    }
    if(test_memcopy_non_blocking()) {
        ERROR_UNPRIV_RAW("[DMA-350 Partition] Non-blocking memcopy test failed\n");
        failed = true;
    }

    if(!failed) {
        INFO_UNPRIV_RAW("[DMA-350 Partition] All tests passed\r\n\n");
    }

    /*
     * This is a dummy psa_wait to let SPM check possible scheduling.
     * It does not expect any signals.
     */
    psa_wait(PSA_WAIT_ANY, PSA_BLOCK);
    psa_panic();
}
