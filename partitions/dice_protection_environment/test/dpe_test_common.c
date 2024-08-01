/*
 * Copyright (c) 2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dice_protection_environment.h"
#include "dpe_test.h"
#include "dpe_test_common.h"
#include "dpe_test_data.h"
#include "dpe_test_private.h"

#include "test_framework.h" /* TEST_LOG(..) */

extern int retained_rot_ctx_handle;

int build_certificate_chain(const struct dpe_test_data_t *td)
{
    dpe_error_t dpe_err;
    int in_handle, new_ctx_handle, new_parent_ctx_handle;
    int i, j;

    in_handle = retained_rot_ctx_handle;

    for (i = 0; i < td->test_count; i++) {

        dpe_err = dpe_derive_context(in_handle,                 /* input_ctx_handle */
                                     td->test_data_in[i].cert_id, /* cert_id */
                                     td->test_data_in[i].retain_parent_context,       /* retain_parent_context */
                                     td->test_data_in[i].allow_new_context_to_derive, /* allow_new_context_to_derive */
                                     td->test_data_in[i].create_certificate,          /* create_certificate */
                                     &td->test_data_in[i].dice_inputs,                 /* dice_inputs */
                                     TFM_TEST_LOCALITY,         /* target_locality */
                                     false,                     /* return_certificate */
                                     true,                      /* allow_new_context_to_export */
                                     false,                     /* export_cdi */
                                     &new_ctx_handle,           /* new_context_handle */
                                     &new_parent_ctx_handle,    /* new_parent_context_handle */
                                     NULL,                      /* new_certificate_buf */
                                     0,                         /* new_certificate_buf_size */
                                     NULL,                      /* new_certificate_actual_size */
                                     NULL,                      /* exported_cdi_buf */
                                     0,                         /* exported_cdi_buf_size */
                                     NULL);                     /* exported_cdi_actual_size */

        if (dpe_err != DPE_NO_ERROR) {
            return -1 ;
        }

        if (i == 0) {
            /* Save RoT context handle for subsequent tests */
            retained_rot_ctx_handle = new_parent_ctx_handle;
            TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);
        }

        td->test_data_out[i].context_handle = new_ctx_handle;
        /* Avoid to be deleted because it is used later as retained_rot_ctx_handle */
        if (i != 0 ) {
            td->test_data_out[i].parent_context_handle = new_parent_ctx_handle;
        }

        /* Invalidate used context_handle or parent_context_handle */
        for (j = 0; j < i; ++j) {
            if (td->test_data_out[j].context_handle == in_handle) {
                td->test_data_out[j].context_handle = INVALID_HANDLE;
            }
            if (td->test_data_out[j].parent_context_handle == in_handle) {
                td->test_data_out[j].parent_context_handle = INVALID_HANDLE;
            }
        }

        /* Update the input handle for next iteration */
        if (td->test_data_in[i].use_parent_handle) {
            in_handle = new_parent_ctx_handle;
        } else {
            in_handle = new_ctx_handle;
        }
    }

    return 0;
}

static int destroy_single_context(int ctx_handle)
{
    dpe_error_t dpe_err;

    if (ctx_handle != INVALID_HANDLE) {
        dpe_err = dpe_destroy_context(ctx_handle, false);
        if (dpe_err != DPE_NO_ERROR) {
            return -1;
        }
    }

    return 0;
}

int destroy_multiple_context(const struct dpe_test_data_t *td)
{
    int i, ret = 0;

    for (i = td->test_count - 1; i >= 0; i-- ) {
        ret |= destroy_single_context(td->test_data_out[i].context_handle);
        td->test_data_out[i].context_handle = INVALID_HANDLE;

        ret |= destroy_single_context(td->test_data_out[i].parent_context_handle);
        td->test_data_out[i].parent_context_handle = INVALID_HANDLE;
    }

    return ret;
}

void update_context_handle(const struct dpe_test_data_t *td,
                           int old_ctx_handle,
                           int new_ctx_handle)
{
    int i;

    for (i = td->test_count - 1; i >= 0; i-- ) {
        if (td->test_data_out[i].context_handle == old_ctx_handle) {
            td->test_data_out[i].context_handle = new_ctx_handle;
        }
        if (td->test_data_out[i].parent_context_handle == old_ctx_handle) {
            td->test_data_out[i].parent_context_handle = new_ctx_handle;
        }
    }
}

int get_last_context_handle(const struct dpe_test_data_t *td)
{
    int len = td->test_count;

    return td->test_data_out[len - 1].context_handle;
}
