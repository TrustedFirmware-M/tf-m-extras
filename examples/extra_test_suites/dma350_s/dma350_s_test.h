/*
 * Copyright (c) 2022, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __DMA350_S_TESTS_H__
#define __DMA350_S_TESTS_H__

#include "extra_tests_common.h"

#ifdef __cplusplus
extern "C" {
#endif

const struct extra_tests_t plat_s_t;

/**
 * \brief Platform specific secure test function.
 *
 * \returns Return EXTRA_TEST_SUCCESS if succeeds. Otherwise, return
 *          EXTRA_TEST_FAILED.
 */
int32_t dma350_s_test(void);

#ifdef __cplusplus
}
#endif

#endif /* __DMA350_S_TESTS_H__ */
