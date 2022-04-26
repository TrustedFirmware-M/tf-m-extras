/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __ETSS_NS_TESTS_H__
#define __ETSS_NS_TESTS_H__

#include "test_framework.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Register testsuite for the PSA external trusted secure storage NS
 *        interface tests.
 *
 * \param[in] p_test_suite  The test suite to be executed.
 */
void register_testsuite_ns_etss_interface(struct test_suite_t *p_test_suite);

#ifdef __cplusplus
}
#endif

#endif /* __PS_NS_TESTS_H__ */
