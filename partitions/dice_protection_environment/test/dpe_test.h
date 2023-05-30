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

/* Below defined values MUST be identical to service internal definitions (dpe_context_mngr.h) */
#define INVALID_HANDLE 0xFFFFFFFF
#define ROT_CTX_HANDLE 0

/* Most significant 16 bits represent nonce & remaining 16 bits represent component index */
#define GET_IDX(handle) (handle & 0xffff)
#define GET_NONCE(handle) ((handle >> 16) & 0xffff)
#define SET_IDX(handle, idx) ((handle & 0xffff0000) | idx)
#define SET_NONCE(handle, nonce) ((handle & 0x00ffff) | (nonce << 16))

/**
 * \brief Derive RoT context for the tests.
 *
 * \param[out] ret  Test result
 */
void derive_rot_layer_context(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveChild API.
 *
 * \param[out] ret  Test result
 */
void derive_child_api_test(struct test_result_t *ret);

/**
 * \brief Test the DPE CertifyKey API.
 *
 * \param[out] ret  Test result
 */
void certify_key_api_test(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveChild with invalid handle.
 *
 * \param[out] ret  Test result
 */
void derive_child_incorrect_handle_test(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveChild with invalid measurement descriptor size.
 *
 * \param[out] ret  Test result
 */
void derive_child_invalid_hash_size_test(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveChild with invalid signer id descriptor size.
 *
 * \param[out] ret  Test result
 */
void derive_child_invalid_signer_id_size_test(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveChild with invalid config descriptor size.
 *
 * \param[out] ret  Test result
 */
void derive_child_invalid_config_desc_size_test(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveChild with missing required arguments.
 *
 * \param[out] ret  Test result
 */
void derive_child_missing_dice_input_arg_test(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveChild with invalid cbor encoded input.
 *
 * \param[out] ret  Test result
 */
void derive_child_invalid_cbor_encoded_input_test(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveChild with same handle again.
 *
 * \param[out] ret  Test result
 */
void derive_child_single_use_handle_test(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveChild for leaf component.
 *
 * \param[out] ret  Test result
 */
void derive_child_with_parent_leaf_component_test(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveChild functionality.
 *
 * \param[out] ret  Test result
 */
void derive_child_core_functionality_test(struct test_result_t *ret);

#ifdef __cplusplus
}
#endif

#endif /* __DPE_TEST_H__ */
