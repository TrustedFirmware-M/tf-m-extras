/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __DPE_DERIVE_CONTEXT_TEST_DATA_H__
#define __DPE_DERIVE_CONTEXT_TEST_DATA_H__

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_NUM_OF_COMPONENTS 30
#define INVALID_COMPONENT_IDX 0xFFFF

#define DERIVE_CONTEXT_TEST_DATA1_SIZE 3
#define DERIVE_CONTEXT_TEST_DATA2_SIZE 1

#define DEFAULT_DICE_INPUT {                               \
        { 0xC0, 0xDE },                                    \
        (uint8_t[]){ 0xC0, 0xDE, 0xDE, 0x5C },             \
        sizeof((uint8_t[]){ 0xC0, 0xDE, 0xDE, 0x5C }),     \
        kDiceConfigTypeDescriptor,                         \
        { 0xC0, 0x9F, 0x16 },                              \
        (uint8_t[]){ 0xC0, 0x9F, 0xDE, 0x5C },             \
        sizeof((uint8_t[]){ 0xC0, 0x9F, 0xDE, 0x5C }),     \
        { 0x47, 0x07 },                                    \
        (uint8_t[]){ 0x47, 0x07, 0xDE, 0x5C },             \
        sizeof((uint8_t[]){ 0x47, 0x07, 0xDE, 0x5C }),     \
        kDiceModeDebug,                                    \
        { 0x81, 0xDE },                                    \
    }

struct dpe_derive_context_test_input_data_t {
    /* If below flag is true, use previous parent handle or use derived context handle */
    bool use_parent_handle;
    bool retain_parent_context;
    bool allow_new_context_to_derive;
    bool create_certificate;
};

struct dpe_derive_context_test_data_t {
    struct dpe_derive_context_test_input_data_t inputs;
};

#ifdef __cplusplus
}
#endif

#endif /* __DPE_DERIVE_CONTEXT_TEST_DATA_H__ */
