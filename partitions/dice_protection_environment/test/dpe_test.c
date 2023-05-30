/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dpe_test.h"
#include "dice_protection_environment.h"

void certify_key_api_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int context_handle = 4;
    bool retain_context = true;
    const uint8_t public_key[] = { 0x1C, 0xEE };
    const uint8_t label[] = { 0x1A, 0xBE, 0x1 };
    uint8_t certificate_chain_buf[128];
    size_t certificate_chain_actual_size;
    uint8_t derived_public_key_buf[64];
    size_t derived_public_key_actual_size;
    int new_context_handle;

    dpe_err = dpe_certify_key(context_handle, retain_context, public_key,
                              sizeof(public_key), label, sizeof(label),
                              certificate_chain_buf,
                              sizeof(certificate_chain_buf),
                              &certificate_chain_actual_size,
                              derived_public_key_buf,
                              sizeof(derived_public_key_buf),
                              &derived_public_key_actual_size,
                              &new_context_handle);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE CertifyKey call failed");
        return;
    }

    TEST_LOG("certificate_chain = %s\r\n", certificate_chain_buf);
    TEST_LOG("derived_public_key = %s\r\n", derived_public_key_buf);
    TEST_LOG("new_context_handle = %d\r\n", new_context_handle);

    ret->val = TEST_PASSED;
}
