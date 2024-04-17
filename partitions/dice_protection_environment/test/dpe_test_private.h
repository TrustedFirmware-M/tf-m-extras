/*
 * Copyright (c) 2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __DPE_TEST_PRIVATE_H__
#define __DPE_TEST_PRIVATE_H__

#ifdef __cplusplus
extern "C" {
#endif

#define DESTROY_SINGLE_CONTEXT(ctx_handle)                          \
            dpe_err = dpe_destroy_context(ctx_handle, false);       \
            if (dpe_err != DPE_NO_ERROR) {                          \
                TEST_FAIL("DPE DestroyContext call failed");        \
                return;                                             \
            }

#ifdef __cplusplus
}
#endif

#endif /* __DPE_TEST_PRIVATE_H__ */
