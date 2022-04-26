/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __ETSS_TESTS_H__
#define __ETSS_TESTS_H__

#include "test_framework.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Register testsuite for the external trusted secure storage secure
 *        interface tests.
 *
 * \param[in] p_test_suite  The test suite to be executed.
 */
void register_testsuite_s_psa_etss_interface(struct test_suite_t *p_test_suite);

/**
 * \brief Register testsuite for the etss reliability tests.
 *
 * \param[in] p_test_suite  The test suite to be executed.
 */
void register_testsuite_s_psa_etss_reliability(struct test_suite_t *p_test_suite);


#ifdef __cplusplus
}
#endif

#endif /* __ETSS_TESTS_H__ */
