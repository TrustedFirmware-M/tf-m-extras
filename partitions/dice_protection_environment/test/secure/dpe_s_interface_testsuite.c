/*
 * Copyright (c) 2023-2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dpe_test.h"

static struct test_t dpe_s_tests[] = {
    {&derive_rot_certificate_context, "DPE_S_TEST_INIT",
     "DPE derive RoT context"},
    {&derive_context_api_test, "DPE_S_TEST_1001",
     "DPE DeriveContext API"},
    {&certify_key_api_test, "DPE_S_TEST_1002",
     "DPE CertifyKey API"},
    {&derive_context_incorrect_handle_test, "DPE_S_TEST_1003",
     "DPE DeriveContext - invalid handle"},
    {&derive_context_invalid_hash_size_test, "DPE_S_TEST_1004",
     "DPE DeriveContext - invalid measurement descriptor size"},
    {&derive_context_invalid_signer_id_size_test, "DPE_S_TEST_1005",
     "DPE DeriveContext - invalid signer id descriptor size"},
    {&derive_context_invalid_config_desc_size_test, "DPE_S_TEST_1006",
     "DPE DeriveContext - invalid config descriptor size"},
    {&derive_context_missing_dice_input_arg_test, "DPE_S_TEST_1007",
     "DPE DeriveContext - missing required dice input arguments"},
    {&derive_context_invalid_cbor_encoded_input_test, "DPE_S_TEST_1008",
     "DPE DeriveContext - invalid cbor encoded input"},
    {&derive_context_smaller_cert_buffer_test, "DPE_S_TEST_1009",
     "DPE DeriveContext - invalid certificate buffer size"},
    {&derive_context_smaller_cdi_buffer_test, "DPE_S_TEST_1010",
     "DPE DeriveContext - invalid CDI buffer size"},
    {&derive_context_prevent_cdi_export_test, "DPE_S_TEST_1011",
     "DPE DeriveContext - check function of allow_new_context_to_export arg"},
    {&derive_context_invalid_input_param_combination_test, "DPE_S_TEST_1012",
     "DPE DeriveContext - invalid input combination of various input args"},
    {&derive_context_missing_req_input_param_combination_test, "DPE_S_TEST_1013",
     "DPE DeriveContext - missing required input arguments in combination"},
    {&derive_context_check_export_cdi_test, "DPE_S_TEST_1014",
     "DPE DeriveContext - check function of export_cdi arg"},
    {&derive_context_single_use_handle_test, "DPE_S_TEST_1015",
     "DPE DeriveContext - same handle"},
    {&derive_context_without_cert_id_test, "DPE_S_TEST_1016",
     "DPE DeriveContext - without cert_id parameter"},
    {&derive_context_with_unsupported_params_test, "DPE_S_TEST_1017",
     "DPE DeriveContext - with unsupported parameters"},
    {&derive_context_with_invalid_target_locality_test, "DPE_S_TEST_1018",
     "DPE DeriveContext - invalid target locality"},
    {&certify_key_core_functionality_test_01, "DPE_S_TEST_1019",
     "DPE CertifyKey functionality - finalised certificate context"},
    {&certify_key_core_functionality_test_02, "DPE_S_TEST_1020",
     "DPE CertifyKey functionality - unfinished certificate context"},
    {&certify_key_retain_context_test, "DPE_S_TEST_1021",
     "DPE CertifyKey - retain context"},
    {&certify_key_incorrect_handle_test, "DPE_S_TEST_1022",
     "DPE CertifyKey - invalid handle"},
    {&certify_key_supplied_pub_key_test, "DPE_S_TEST_1023",
     "DPE CertifyKey - supplied public key"},
    {&certify_key_supplied_label_test, "DPE_S_TEST_1024",
     "DPE CertifyKey - supplied label"},
    {&certify_key_smaller_cert_buffer_test, "DPE_S_TEST_1025",
     "DPE CertifyKey - invalid certificate chain buffer size"},
    {&certify_key_smaller_derived_pub_key_buffer_test, "DPE_S_TEST_1026",
     "DPE CertifyKey - invalid public key buffer size"},
    {&certify_key_invalid_cbor_encoded_input_test, "DPE_S_TEST_1027",
     "DPE CertifyKey - invalid cbor encoded input"},
    {&certify_key_without_optional_args_test, "DPE_S_TEST_1028",
     "DPE CertifyKey - without optional arguments"},
    {&certify_key_with_unsupported_params_test, "DPE_S_TEST_1029",
     "DPE CertifyKey - with unsupported parameters"},
    {&derive_context_with_parent_leaf_component_test, "DPE_S_TEST_1030",
     "DPE DeriveContext - Leaf component"},
    {&get_certificate_chain_test, "DPE_S_TEST_1031",
     "DPE GetCertificateChain - validate certificate chain"},
    {&complex_sequence_test_1, "DPE_S_TEST_1032",
     "DPE complex sequence test 1"},
    {&derive_context_without_cert_id_multiple_ctx_test, "DPE_S_TEST_1033",
     "DPE DeriveContext - without cert_id parameter multiple context test"},
    {&derive_context_mixing_cert_id_negative_test, "DPE_S_TEST_1034",
     "DPE DeriveContext - Calling derive context with no cert_id on "
     "non-finalised certificate"},
    {&derive_context_mixing_cert_id_multiple_ctx_test, "DPE_S_TEST_1035",
     "DPE DeriveContext - with and without cert_id parameter multiple context test"},

    /*
     * This destroys the RoT handle since retain_parent_context is false,
     * hence RoT context handle is destroyed. As a result the
     * retained_rot_handle variable cannot be used anymore between subsequent
     * test cases to pass a valid handle.
     */
    {&derive_context_without_optional_args_test, "DPE_S_TEST_MUST_BE_THE_LAST",
     "DPE DeriveContext - without optional arguments"},
};

void register_testsuite_extra_s_interface(struct test_suite_t *p_test_suite)
{
    uint32_t list_size;

    list_size = sizeof(dpe_s_tests) / sizeof(dpe_s_tests[0]);

    set_testsuite("DPE Secure Tests (DPE_S_TEST_1XXX)",
                  dpe_s_tests, list_size, p_test_suite);
}
