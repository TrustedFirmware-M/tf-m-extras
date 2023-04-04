/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dpe_test.h"

#include "dice_protection_environment.h"

void dpe_test_1001(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int context_handle = 42;
    bool retain_parent_context = false;
    bool allow_child_to_derive = false;
    bool create_certificate = false;
    DiceInputValues dice_inputs = {
        { 0xC0, 0xDE },
        (uint8_t[]){ 0xC0, 0xDE, 0xDE, 0x5C },
        sizeof((uint8_t[]){ 0xC0, 0xDE, 0xDE, 0x5C }),
        kDiceConfigTypeDescriptor,
        { 0xC0, 0x9F, 0x16 },
        (uint8_t[]){ 0xC0, 0x9F, 0xDE, 0x5C },
        sizeof((uint8_t[]){ 0xC0, 0x9F, 0xDE, 0x5C }),
        { 0x47, 0x07 },
        (uint8_t[]){ 0x47, 0x07, 0xDE, 0x5C },
        sizeof((uint8_t[]){ 0x47, 0x07, 0xDE, 0x5C }),
        kDiceModeDebug,
        { 0x81, 0xDE },
    };
    int child_context_handle;
    int new_context_handle;

    dpe_err = dpe_derive_child(context_handle, retain_parent_context,
                               allow_child_to_derive, create_certificate,
                               &dice_inputs, &child_context_handle,
                               &new_context_handle);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveChild call failed");
        return;
    }

    TEST_LOG("child_context_handle = %d\r\n", child_context_handle);
    TEST_LOG("new_context_handle = %d\r\n", new_context_handle);

    ret->val = TEST_PASSED;
}

void dpe_test_1002(struct test_result_t *ret)
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
