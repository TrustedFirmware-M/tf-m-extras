/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __DPE_DERIVE_CHILD_TEST_DATA_H__
#define __DPE_DERIVE_CHILD_TEST_DATA_H__

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_NUM_OF_COMPONENTS 30

#define DERIVE_CHILD_TEST_DATA1_SIZE 16

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

struct dpe_derive_child_test_input_data_t {
    uint16_t in_handle_comp_idx;
    bool retain_parent_context;
    bool allow_child_to_derive;
    bool create_certificate;
};

struct dpe_derive_child_test_output_data_t {
    uint16_t expected_child_handle_idx;
    uint16_t expected_parent_handle_idx;
};

struct dpe_derive_child_test_data_t {
    struct dpe_derive_child_test_input_data_t inputs;
    struct dpe_derive_child_test_output_data_t outputs;
};

#ifdef __cplusplus
}
#endif

#endif /* __DPE_DERIVE_CHILD_TEST_DATA_H__ */
