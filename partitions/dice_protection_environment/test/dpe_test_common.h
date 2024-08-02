/*
 * Copyright (c) 2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __DPE_TEST_COMMON_H__
#define __DPE_TEST_COMMON_H__

#include "dpe_test_data.h"

#ifdef __cplusplus
extern "C" {
#endif

int build_certificate_chain(const struct dpe_test_data_t *test_data);

int destroy_multiple_context(const struct dpe_test_data_t *test_data);

void update_context_handle(const struct dpe_test_data_t *test_data,
                           int old_ctx_handle,
                           int new_ctx_handle);

int get_last_context_handle(const struct dpe_test_data_t *td);

int get_context_handle_from_fw_id(const struct dpe_test_data_t *td, enum fw_id id);

#ifdef __cplusplus
}
#endif

#endif /* __DPE_TEST_COMMON_H__ */
