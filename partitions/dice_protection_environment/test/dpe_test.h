/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __DPE_TEST_H__
#define __DPE_TEST_H__

#include "test_framework.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Test the DPE DeriveChild API.
 *
 * \param[out] ret  Test result
 */
void dpe_test_1001(struct test_result_t *ret);

/**
 * \brief Test the DPE CertifyKey API.
 *
 * \param[out] ret  Test result
 */
void dpe_test_1002(struct test_result_t *ret);

#ifdef __cplusplus
}
#endif

#endif /* __DPE_TEST_H__ */
