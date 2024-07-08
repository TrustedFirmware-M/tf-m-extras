/*
 * Copyright (c) 2023-2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __DPE_TEST_H__
#define __DPE_TEST_H__

#include "psa/crypto.h"
#include "test_framework.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Below defined values MUST be identical to service internal definitions (dpe_context_mngr.h) */
#define INVALID_HANDLE 0xFFFFFFFF
#define ROT_CTX_HANDLE 0
#define DPE_ATTEST_PUB_KEY_SIZE PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(521)
/* Below encoded CDI size accomodate both Attest and Seal CDI */
#define DICE_MAX_ENCODED_CDI_SIZE ((2 * DICE_CDI_SIZE) + 16)

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
void derive_rot_certificate_context(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveContext API.
 *
 * \param[out] ret  Test result
 */
void derive_context_api_test(struct test_result_t *ret);

/**
 * \brief Test the DPE CertifyKey API.
 *
 * \param[out] ret  Test result
 */
void certify_key_api_test(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveContext with invalid handle.
 *
 * \param[out] ret  Test result
 */
void derive_context_incorrect_handle_test(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveContext with invalid measurement descriptor size.
 *
 * \param[out] ret  Test result
 */
void derive_context_invalid_hash_size_test(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveContext with invalid signer id descriptor size.
 *
 * \param[out] ret  Test result
 */
void derive_context_invalid_signer_id_size_test(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveContext with invalid config descriptor size.
 *
 * \param[out] ret  Test result
 */
void derive_context_invalid_config_desc_size_test(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveContext with missing required arguments.
 *
 * \param[out] ret  Test result
 */
void derive_context_missing_dice_input_arg_test(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveContext with invalid cbor encoded input.
 *
 * \param[out] ret  Test result
 */
void derive_context_invalid_cbor_encoded_input_test(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveContext with smaller certificate buffer size.
 *
 * \param[out] ret  Test result
 */
void derive_context_smaller_cert_buffer_test(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveContext with smaller CDI buffer size.
 *
 * \param[out] ret  Test result
 */
void derive_context_smaller_cdi_buffer_test(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveContext to check functionality of
 *        allow_new_context_to_export argument.
 *
 * \param[out] ret  Test result
 */
void derive_context_prevent_cdi_export_test(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveContext with invalid input combination of
 *        various input arguments.
 *
 * \param[out] ret  Test result
 */
void derive_context_invalid_input_param_combination_test(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveContext with missing some inputs required in
 *        combination.
 *
 * \param[out] ret  Test result
 */
void derive_context_missing_req_input_param_combination_test(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveContext to check for export CDI.
 *
 * \param[out] ret  Test result
 */
void derive_context_check_export_cdi_test(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveContext with same handle again.
 *
 * \param[out] ret  Test result
 */
void derive_context_single_use_handle_test(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveContext without cert id argument.
 *
 * \param[out] ret  Test result
 */
void derive_context_without_cert_id_test(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveContext without cert id argument 2.
 *
 * \param[out] ret  Test result
 */
void derive_context_without_cert_id_multiple_ctx_test(struct test_result_t *ret);

/**
 * \brief Mix use of custom arg (cert_id) and without it.
 *        1) Call DeriveContext using cert_id argument, do not finalise the
 *           certificate and call DeriveContext without cert_id argument.
 *        2) Call DeriveContext without cert_id argument, do not finalise the
 *           certificate and call DeriveContext with cert_id argument.
 *
 * \param[out] ret  Test result
 */
void derive_context_mixing_cert_id_negative_test(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveContext with unsupported parameters.
 *
 * \param[out] ret  Test result
 */
void derive_context_with_unsupported_params_test(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveContext with invalid target locality.
 *
 * \param[out] ret  Test result
 */
void derive_context_with_invalid_target_locality_test(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveContext for leaf component.
 *
 * \param[out] ret  Test result
 */
void derive_context_with_parent_leaf_component_test(struct test_result_t *ret);

/**
 * \brief Test the DPE DeriveContext without optional arguments.
 *
 * \param[out] ret  Test result
 */
void derive_context_without_optional_args_test(struct test_result_t *ret);

/**
 * \brief Test the DPE CertifyKey with finalized certificate context.
 *        Note: this test will create context(s) which cannot be destroyed.
 *
 * \param[out] ret  Test result
 */
void certify_key_core_functionality_test_01(struct test_result_t *ret);

/**
 * \brief Test the DPE CertifyKey with unfinished certificate context.
 *        Note: this test will create context(s) which cannot be destroyed.
 *
 * \param[out] ret  Test result
 */
void certify_key_core_functionality_test_02(struct test_result_t *ret);

/**
 * \brief Test the DPE CertifyKey with invalid handle.
 *
 * \param[out] ret  Test result
 */
void certify_key_incorrect_handle_test(struct test_result_t *ret);

/**
 * \brief Test the DPE CertifyKey functionality for retaining context.
 *
 * \param[out] ret  Test result
 */
void certify_key_retain_context_test(struct test_result_t *ret);

/**
 * \brief Test the DPE CertifyKey with supplied public key.
 *
 * \param[out] ret  Test result
 */
void certify_key_supplied_pub_key_test(struct test_result_t *ret);

/**
 * \brief Test the DPE CertifyKey with supplied label.
 *
 * \param[out] ret  Test result
 */
void certify_key_supplied_label_test(struct test_result_t *ret);

/**
 * \brief Test the DPE CertifyKey with smaller certificate buffer size.
 *
 * \param[out] ret  Test result
 */
void certify_key_smaller_cert_buffer_test(struct test_result_t *ret);

/**
 * \brief Test the DPE CertifyKey with smaller public key buffer size.
 *
 * \param[out] ret  Test result
 */
void certify_key_smaller_derived_pub_key_buffer_test(struct test_result_t *ret);

/**
 * \brief Test the DPE CertifyKey with invalid cbor encoded input.
 *
 * \param[out] ret  Test result
 */
void certify_key_invalid_cbor_encoded_input_test(struct test_result_t *ret);

/**
 * \brief Test the DPE CertifyKey without optional arguments.
 *
 * \param[out] ret  Test result
 */
void certify_key_without_optional_args_test(struct test_result_t *ret);

/**
 * \brief Test the DPE CertifyKey with unsupported parameters.
 *
 * \param[out] ret  Test result
 */
void certify_key_with_unsupported_params_test(struct test_result_t *ret);

/**
 * \brief Test the DPE GetCertificateChain API.
 *
 * \param[out] ret  Test result
 */
void get_certificate_chain_test(struct test_result_t *ret);

/**
 * \brief Test complex sequence for DPE GetCertificateChain and CertifyKey.
 *
 * \param[out] ret  Test result
 */
void complex_sequence_test_1(struct test_result_t *ret);

#ifdef __cplusplus
}
#endif

#endif /* __DPE_TEST_H__ */
