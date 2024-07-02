/*
 * Copyright (c) 2023-2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <string.h>
#include "dice_protection_environment.h"
#include "../dpe_certificate_common.h"
#include "dpe_test.h"
#include "dpe_test_data.h"
#include "dpe_test_private.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_spiffy_decode.h"

extern int retained_rot_ctx_handle;

void derive_context_api_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    struct derive_context_cmd_input_t dc_input = DEFAULT_DC_CMD_INPUT;
    struct derive_context_cmd_output_t dc_output = {0};

    dc_input.context_handle = retained_rot_ctx_handle;

    dpe_err = CALL_DERIVE_CONTEXT(dc_input, dc_output);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveContext call failed");
        return;
    }

    DESTROY_SINGLE_CONTEXT(dc_output.out_ctx_handle);

    /* Save the last handle for the subsequent test */
    retained_rot_ctx_handle = dc_output.out_parent_handle;
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);

    ret->val = TEST_PASSED;
}

void derive_rot_certificate_context(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    struct derive_context_cmd_input_t dc_input = DEFAULT_DC_CMD_INPUT;
    struct derive_context_cmd_output_t dc_output = {0};

    dc_input.context_handle = ROT_CTX_HANDLE;
    dc_input.create_certificate = true;
    dc_input.cert_id = DPE_ROT_CERT_ID;

    dpe_err = CALL_DERIVE_CONTEXT(dc_input, dc_output);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveContext RoT context init failed");
        return;
    }

    retained_rot_ctx_handle = dc_output.out_ctx_handle;
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);
    ret->val = TEST_PASSED;
}

void derive_context_single_use_handle_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    struct derive_context_cmd_input_t dc_input = DEFAULT_DC_CMD_INPUT;
    struct derive_context_cmd_output_t dc_output = {0};

    dc_input.context_handle = retained_rot_ctx_handle;

    dpe_err = CALL_DERIVE_CONTEXT(dc_input, dc_output);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveContext call failed");
        return;
    }

    /* Save the last handle for the subsequent test */
    retained_rot_ctx_handle = dc_output.out_parent_handle;
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);

    /* Use the previously used handle again */
    dpe_err = CALL_DERIVE_CONTEXT(dc_input, dc_output);
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveContext test: Same handle used again "
                  "should return invalid argument");
        return;
    }

    DESTROY_SINGLE_CONTEXT(dc_output.out_ctx_handle);

    ret->val = TEST_PASSED;
}

void derive_context_incorrect_handle_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    struct derive_context_cmd_input_t dc_input = DEFAULT_DC_CMD_INPUT;
    struct derive_context_cmd_output_t dc_output = {0};

    /* Use a different handle index */
    dc_input.context_handle = SET_IDX(retained_rot_ctx_handle,
                                     (GET_IDX(retained_rot_ctx_handle) + 1));

    dpe_err = CALL_DERIVE_CONTEXT(dc_input, dc_output);
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveContext test: Invalid handle index "
                  "should return invalid argument");
        return;
    }

    /* Use a different handle nonce */
    dc_input.context_handle = SET_NONCE(retained_rot_ctx_handle,
                                       (GET_NONCE(retained_rot_ctx_handle) + 1));

    dpe_err = CALL_DERIVE_CONTEXT(dc_input, dc_output);
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveContext test: Invalid handle nonce "
                  "should return invalid argument");
        return;
    }

    ret->val = TEST_PASSED;
}

void derive_context_invalid_hash_size_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    struct derive_context_cmd_input_t dc_input = DEFAULT_DC_CMD_INPUT;
    struct derive_context_cmd_output_t dc_output = {0};

    /* Use an invalid size of measurement descriptor */
    dc_input.dice_inputs.code_descriptor_size = DICE_CODE_DESCRIPTOR_MAX_SIZE + 1;
    dc_input.context_handle = retained_rot_ctx_handle;

    dpe_err = CALL_DERIVE_CONTEXT(dc_input, dc_output);
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveContext test: Invalid measurement descriptor size "
                  "should return invalid argument");
        return;
    }

    ret->val = TEST_PASSED;
}

void derive_context_invalid_signer_id_size_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    struct derive_context_cmd_input_t dc_input = DEFAULT_DC_CMD_INPUT;
    struct derive_context_cmd_output_t dc_output = {0};

    /* Use an invalid size of signer id descriptor */
    dc_input.dice_inputs.authority_descriptor_size = DICE_AUTHORITY_DESCRIPTOR_MAX_SIZE + 1;
    dc_input.context_handle = retained_rot_ctx_handle;

    dpe_err = CALL_DERIVE_CONTEXT(dc_input, dc_output);
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveContext test: Invalid signer id descriptor size "
                  "should return invalid argument");
        return;
    }

    ret->val = TEST_PASSED;
}

void derive_context_invalid_config_desc_size_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    struct derive_context_cmd_input_t dc_input = DEFAULT_DC_CMD_INPUT;
    struct derive_context_cmd_output_t dc_output = {0};

    /* Use an invalid size of config descriptor */
    dc_input.dice_inputs.config_descriptor_size = DICE_CONFIG_DESCRIPTOR_MAX_SIZE + 1;
    dc_input.context_handle = retained_rot_ctx_handle;

    dpe_err = CALL_DERIVE_CONTEXT(dc_input, dc_output);
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveContext test: Invalid config descriptor size "
                  "should return invalid argument");
        return;
    }

    ret->val = TEST_PASSED;
}

void derive_context_missing_dice_input_arg_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    struct dpe_derive_context_test_params_t test_params = {0};
    struct derive_context_cmd_input_t dc_input = DEFAULT_DC_CMD_INPUT;
    struct derive_context_cmd_output_t dc_output = {0};

    ADD_CERT_BUF(dc_output, DICE_CERT_SIZE);
    ADD_EXPORT_CDI_BUF(dc_output, DICE_MAX_ENCODED_CDI_SIZE);

    test_params.is_code_hash_missing = true;
    dpe_err = CALL_DERIVE_CONTEXT_WITH_TEST_PARAM(dc_input, dc_output, test_params);
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveContext test: Invalid dice input (missing hash) "
                  "should return invalid argument");
        return;
    }

    test_params.is_code_hash_missing = false;
    dc_input.dice_inputs.config_type = kDiceConfigTypeDescriptor;
    test_params.is_config_descriptor_missing = true;
    dpe_err = CALL_DERIVE_CONTEXT_WITH_TEST_PARAM(dc_input, dc_output, test_params);
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveContext test: Invalid dice input (missing config descriptor) "
                  "when config_type is 'descriptor' should return invalid argument");
        return;
    }

    test_params.is_config_descriptor_missing = false;
    test_params.is_config_value_missing = true;
    dpe_err = CALL_DERIVE_CONTEXT_WITH_TEST_PARAM(dc_input, dc_output, test_params);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveContext test: Optional dice input (missing config value) "
                  "when config_type is 'descriptor' should NOT return any error");
        return;
    }
    /* Update retained parent handle if context derived successfully in above test */
    retained_rot_ctx_handle = dc_output.out_parent_handle;
    DESTROY_SINGLE_CONTEXT(dc_output.out_ctx_handle);

    dc_input.dice_inputs.config_type = kDiceConfigTypeInline;
    dpe_err = CALL_DERIVE_CONTEXT_WITH_TEST_PARAM(dc_input, dc_output, test_params);
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveContext test: Invalid dice input (missing config value) "
                  "when config_type is 'inline' should return invalid argument");
        return;
    }

    test_params.is_config_value_missing = false;
    test_params.is_config_descriptor_missing = true;
    dpe_err = CALL_DERIVE_CONTEXT_WITH_TEST_PARAM(dc_input, dc_output, test_params);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveContext test: Optional dice input (missing config descriptor) "
                  "when config_type is 'inline' should NOT return any error");
        return;
    }
    /* Update retained parent handle if context derived successfully in above test */
    retained_rot_ctx_handle = dc_output.out_parent_handle;
    DESTROY_SINGLE_CONTEXT(dc_output.out_ctx_handle);

    test_params.is_config_descriptor_missing = false;
    test_params.is_authority_hash_missing = true;
    dpe_err = CALL_DERIVE_CONTEXT_WITH_TEST_PARAM(dc_input, dc_output, test_params);
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveContext test: Invalid dice input (missing authority hash) "
                  "should return invalid argument");
        return;
    }

    test_params.is_authority_hash_missing = false;
    /* authority_descriptor is optional dice input */
    test_params.is_authority_descriptor_missing = true;
    dpe_err = CALL_DERIVE_CONTEXT_WITH_TEST_PARAM(dc_input, dc_output, test_params);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveContext test: Optional dice input (missing authority descriptor) "
                  "should NOT return any error");
        return;
    }
    /* Update retained parent handle if context derived successfully in above test */
    retained_rot_ctx_handle = dc_output.out_parent_handle;
    DESTROY_SINGLE_CONTEXT(dc_output.out_ctx_handle);

    test_params.is_authority_descriptor_missing = false;
    test_params.is_mode_missing = true;
    dpe_err = CALL_DERIVE_CONTEXT_WITH_TEST_PARAM(dc_input, dc_output, test_params);
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveContext test: Invalid dice input (missing mode) "
                  "should return invalid argument");
        return;
    }

    test_params.is_mode_missing = false;
    test_params.is_input_dice_data_missing = true;
    dpe_err = CALL_DERIVE_CONTEXT_WITH_TEST_PARAM(dc_input, dc_output, test_params);
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveContext test: Missing dice input "
                  "should return invalid argument");
        return;
    }

    ret->val = TEST_PASSED;
}

void derive_context_invalid_cbor_encoded_input_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    struct dpe_derive_context_test_params_t test_params = {0};
    struct derive_context_cmd_input_t dc_input = DEFAULT_DC_CMD_INPUT;
    struct derive_context_cmd_output_t dc_output = {0};

    ADD_CERT_BUF(dc_output, DICE_CERT_SIZE);
    ADD_EXPORT_CDI_BUF(dc_output, DICE_MAX_ENCODED_CDI_SIZE);

    test_params.is_encoded_cbor_corrupt = true;

    dpe_err = CALL_DERIVE_CONTEXT_WITH_TEST_PARAM(dc_input, dc_output, test_params);
    if (dpe_err != DPE_INVALID_COMMAND) {
        TEST_FAIL("DPE DeriveContext test: Invalid CBOR construct "
                  "should return invalid command");
        return;
    }

    ret->val = TEST_PASSED;
}

void derive_context_smaller_cert_buffer_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    struct derive_context_cmd_input_t dc_input = DEFAULT_DC_CMD_INPUT;
    struct derive_context_cmd_output_t dc_output = {0};

    ADD_CERT_BUF(dc_output, 1);

    /* Since size of the output parameters is checked by the client side API
     * implementation new context would be derived by the service in this case
     * hence use invalid cert id.
     */
    dc_input.context_handle = retained_rot_ctx_handle;
    dc_input.create_certificate = true;
    dc_input.return_certificate = true;

    dpe_err = CALL_DERIVE_CONTEXT(dc_input, dc_output);
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveContext test: Smaller certificate buffer "
                  "should return invalid argument");
        return;
    }

    DESTROY_SINGLE_CONTEXT(dc_output.out_ctx_handle);

    /* Save the last handle for the subsequent test */
    retained_rot_ctx_handle = dc_output.out_parent_handle;
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);

    ret->val = TEST_PASSED;
}

void derive_context_smaller_cdi_buffer_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    struct derive_context_cmd_input_t dc_input = DEFAULT_DC_CMD_INPUT;
    struct derive_context_cmd_output_t dc_output = {0};

    ADD_EXPORT_CDI_BUF(dc_output, 1);

    /* Since size of the output parameters is checked by the client side API
     * implementation new context would be derived by the service in this case
     * hence use invalid cert id.
     */
    dc_input.context_handle = retained_rot_ctx_handle;
    dc_input.create_certificate = true;
    dc_input.export_cdi = true;
    dc_input.cert_id = DPE_UNDESTROYABLE_CTX_CERT_ID_1;

    dpe_err = CALL_DERIVE_CONTEXT(dc_input, dc_output);
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveContext test: Smaller CDI buffer "
                  "should return invalid argument");
        return;
    }

    /* NOTE: When CDI is exported, it creates an undestroyable context */
    /* Save the last handle for the subsequent test */
    retained_rot_ctx_handle = dc_output.out_parent_handle;
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);

    ret->val = TEST_PASSED;
}

void derive_context_prevent_cdi_export_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    struct derive_context_cmd_input_t dc_input = DEFAULT_DC_CMD_INPUT;
    struct derive_context_cmd_output_t dc_output = {0};

    dc_input.context_handle = retained_rot_ctx_handle;
    dc_input.allow_new_context_to_export = false;

    dpe_err = CALL_DERIVE_CONTEXT(dc_input, dc_output);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveContext call failed");
        return;
    }

    /* Save the last handle for the subsequent test */
    retained_rot_ctx_handle = dc_output.out_parent_handle;
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);

    /* Try to export CDI with parent not allowed to export */
    dc_input.context_handle = dc_output.out_ctx_handle;
    dc_input.create_certificate = true;
    dc_input.allow_new_context_to_export = true;
    dc_input.export_cdi = true;

    dpe_err = CALL_DERIVE_CONTEXT(dc_input, dc_output);
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveContext test: If export cdi is requested on context where it is "
                  "prohibited to do so, it should return invalid argument error");
        return;
    }

    DESTROY_SINGLE_CONTEXT(dc_output.out_ctx_handle);

   ret->val = TEST_PASSED;
}

void derive_context_invalid_input_param_combination_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    struct derive_context_cmd_input_t dc_input = DEFAULT_DC_CMD_INPUT;
    struct derive_context_cmd_output_t dc_output = {0};

    /* If allow_new_context_to_export = FALSE, DPE service must not acknowledge
     * export_cdi function
     */
    dc_input.context_handle = retained_rot_ctx_handle;
    dc_input.create_certificate = true;
    dc_input.allow_new_context_to_export = false;
    dc_input.export_cdi = true;

    dpe_err = CALL_DERIVE_CONTEXT(dc_input, dc_output);
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveContext test: request for export cdi with "
                  "allow_new_context_to_export set to FALSE should return invalid argument");
        return;
    }

    /* If create_certificate = FALSE, DPE service must not acknowledge
     * export_cdi function
     */
    dc_input.create_certificate = false;
    dc_input.allow_new_context_to_export = true;

    dpe_err = CALL_DERIVE_CONTEXT(dc_input, dc_output);
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveContext test: request for export cdi with "
                  "create_certificate set to FALSE should return invalid argument");
        return;
    }

   ret->val = TEST_PASSED;
}

void derive_context_missing_req_input_param_combination_test(struct test_result_t *ret)
{
    //TODO: TO BE IMPLEMENTED
    //Q - Is this same as above test derive_context_invalid_input_param_combination_test()?

    ret->val = TEST_PASSED;
}

/* Verifies the CBOR structure of exported CDI data.
 * Exported_CDI = {
 *  1 : bstr .size 32,     ; CDI_Attest
 *  2 : bstr .size 32,     ; CDI_Seal
 * }
 */
static int verify_cdi_encoding(UsefulBufC cdi_buf)
{
    QCBORError qcbor_err;
    QCBORDecodeContext decode_ctx;
    QCBORItem item;

    QCBORDecode_Init(&decode_ctx, cdi_buf, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_EnterMap(&decode_ctx, &item);
    if ((item.uDataType != QCBOR_TYPE_MAP) || (item.val.uCount != 2)) {
        return -1;
    }

    qcbor_err = QCBORDecode_GetNext(&decode_ctx, &item);
    if ((item.label.int64 != DPE_LABEL_CDI_ATTEST) || (item.val.string.len != 32)) {
        return -1;
    }

    qcbor_err = QCBORDecode_GetNext(&decode_ctx, &item);
    if ((item.label.int64 != DPE_LABEL_CDI_SEAL) || (item.val.string.len != 32)) {
        return -1;
    }

    QCBORDecode_ExitMap(&decode_ctx);

    qcbor_err = QCBORDecode_Finish(&decode_ctx);
    if (qcbor_err != QCBOR_SUCCESS) {
        return -1;
    }

    return 0;
}

void derive_context_check_export_cdi_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    struct derive_context_cmd_input_t dc_input = DEFAULT_DC_CMD_INPUT;
    struct derive_context_cmd_output_t dc_output = {0};

    ADD_EXPORT_CDI_BUF(dc_output, DICE_MAX_ENCODED_CDI_SIZE);
    UsefulBufC cdi_buf;

    dc_input.context_handle = retained_rot_ctx_handle;
    dc_input.cert_id = DPE_UNDESTROYABLE_CTX_CERT_ID_2;
    dc_input.create_certificate = true;
    dc_input.export_cdi = true;

    dpe_err = CALL_DERIVE_CONTEXT(dc_input, dc_output);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveContext call failed");
        return;
    }
    /* NOTE: When CDI is exported, it creates an undestroyable context */

    cdi_buf = (UsefulBufC){ dc_output.exported_cdi_buf,
                            dc_output.exported_cdi_actual_size };

    if (verify_cdi_encoding(cdi_buf)) {
        TEST_FAIL("DPE DeriveContext exported CDI verification failed");
        return;
    }

    /* Save the last handle for the subsequent test */
    retained_rot_ctx_handle = dc_output.out_parent_handle;
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);

    ret->val = TEST_PASSED;
}

void derive_context_with_parent_leaf_component_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int saved_handle;
    struct derive_context_cmd_input_t dc_input = DEFAULT_DC_CMD_INPUT;
    struct derive_context_cmd_output_t dc_output = {0};

    /* Call to derive_context for adding component setting it as a leaf */
    dc_input.context_handle = retained_rot_ctx_handle;
    dc_input.allow_new_context_to_derive = false;

    dpe_err = CALL_DERIVE_CONTEXT(dc_input, dc_output);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveContext test: Leaf component derivation failed");
        return;
    }

    saved_handle = dc_output.out_ctx_handle;
    /* Save the last handle for the subsequent test */
    retained_rot_ctx_handle = dc_output.out_parent_handle;
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);

    /* Try to further derive context with parent not allowed to derive as above */
    dc_input.context_handle = dc_output.out_ctx_handle;
    dc_input.retain_parent_context = false;
    dc_input.allow_new_context_to_derive = false;

    dpe_err = CALL_DERIVE_CONTEXT(dc_input, dc_output);
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveContext test: Trying to derive context with parent as leaf should "
                  "return invalid argument ");
        return;
    }

    DESTROY_SINGLE_CONTEXT(saved_handle);

   ret->val = TEST_PASSED;
}

void derive_context_without_cert_id_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    int out_ctx_handle;
    int out_parent_handle;
    DiceInputValues dice_inputs = DEFAULT_DICE_INPUT;
    struct dpe_derive_context_test_params_t test_params = {0};

    test_params.is_cert_id_missing = true;
    dpe_err = dpe_derive_context_with_test_param(retained_rot_ctx_handle, /* input_ctx_handle */
                                                 DPE_CERT_ID_INVALID,     /* cert_id */
                                                 true,                    /* retain_parent_context */
                                                 true,                    /* allow_new_context_to_derive */
                                                 false,                   /* create_certificate */
                                                 &dice_inputs,            /* dice_inputs */
                                                 TFM_TEST_LOCALITY,       /* target_locality */
                                                 false,                   /* return_certificate */
                                                 true,                    /* allow_new_context_to_export */
                                                 false,                   /* export_cdi */
                                                 &out_ctx_handle,         /* new_context_handle */
                                                 &out_parent_handle,      /* new_parent_context_handle */
                                                 NULL,                    /* new_certificate_buf */
                                                 0,                       /* new_certificate_buf_size */
                                                 NULL,                    /* new_certificate_actual_size */
                                                 NULL,                    /* exported_cdi_buf */
                                                 0,                       /* exported_cdi_buf_size */
                                                 NULL,                    /* exported_cdi_actual_size */
                                                 &test_params);           /* test_parameters */
    //NOTE: This test should return DPE_NO_ERROR once related changes are implemented.
    // Also, destroy the derived context and retain parent handle for subsequent tests.
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveContext test: Without optional parameter cert_id should "
                  "return invalid argument");
        return;
    }

    ret->val = TEST_PASSED;
}

void derive_context_with_unsupported_params_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    struct dpe_derive_context_test_params_t test_params = {0};
    struct derive_context_cmd_input_t dc_input = DEFAULT_DC_CMD_INPUT;
    struct derive_context_cmd_output_t dc_output = {0};

    ADD_CERT_BUF(dc_output, DICE_CERT_SIZE);
    ADD_EXPORT_CDI_BUF(dc_output, DICE_MAX_ENCODED_CDI_SIZE);

    test_params.is_unsupported_params_added = true;
    dpe_err = CALL_DERIVE_CONTEXT_WITH_TEST_PARAM(dc_input, dc_output, test_params);
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveContext test: with unsupported parameters should fail");
        return;
    }

    test_params.is_unsupported_dice_params_added = true;
    dpe_err = CALL_DERIVE_CONTEXT_WITH_TEST_PARAM(dc_input, dc_output, test_params);
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveContext test: with unsupported DICE parameters "
                  "should fail");
        return;
    }

    ret->val = TEST_PASSED;
}

void derive_context_with_invalid_target_locality_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    struct derive_context_cmd_input_t dc_input = DEFAULT_DC_CMD_INPUT;
    struct derive_context_cmd_output_t dc_output = {0};
    dc_input.context_handle = retained_rot_ctx_handle;
    /* Use a distinct target_locality for the context to be derived */
    dc_input.target_locality = RANDOM_DISTINCT_LOCALITY;

    dpe_err = CALL_DERIVE_CONTEXT(dc_input, dc_output);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveContext call failed");
        return;
    }
    /* Save the last handle for the subsequent test */
    retained_rot_ctx_handle = dc_output.out_parent_handle;
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);

    /* Parent context has different target locality, now try to use the handle
     * to derive the context from this test partition client and it should fail
     */
    dc_input.context_handle = dc_output.out_ctx_handle;
    dpe_err = CALL_DERIVE_CONTEXT(dc_input, dc_output);
    if (dpe_err != DPE_INVALID_ARGUMENT) {
        TEST_FAIL("DPE DeriveContext test: Invalid target_locality "
                  "should return invalid argument");
        return;
    }
    DESTROY_SINGLE_CONTEXT(dc_output.out_ctx_handle);

    ret->val = TEST_PASSED;
}

void derive_context_without_optional_args_test(struct test_result_t *ret)
{
    dpe_error_t dpe_err;
    struct dpe_derive_context_test_params_t test_params = {0};
    struct derive_context_cmd_input_t dc_input = DEFAULT_DC_CMD_INPUT;
    struct derive_context_cmd_output_t dc_output = {0};

    ADD_CERT_BUF(dc_output, DICE_CERT_SIZE);
    ADD_EXPORT_CDI_BUF(dc_output, DICE_MAX_ENCODED_CDI_SIZE);

    test_params.is_allow_new_context_to_derive_missing = true;
    dpe_err = CALL_DERIVE_CONTEXT_WITH_TEST_PARAM(dc_input, dc_output, test_params);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveContext test: Without optional parameter should not fail");
        return;
    }

    /* Default value of allow_new_context_to_derive = true, hence it should
     * return valid context handle
     */
    if (dc_output.out_ctx_handle == INVALID_HANDLE) {
        TEST_FAIL("DPE DeriveContext test: Without optional parameter should not fail");
        return;
    }
    DESTROY_SINGLE_CONTEXT(dc_output.out_ctx_handle);

    retained_rot_ctx_handle = dc_output.out_parent_handle;
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);
    test_params.is_allow_new_context_to_derive_missing = false;
    test_params.is_create_certificate_missing = true;
    dc_input.return_certificate = true;
    dc_output.certificate_actual_size = 0;
    dpe_err = CALL_DERIVE_CONTEXT_WITH_TEST_PARAM(dc_input, dc_output, test_params);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveContext test: Without optional parameter should not fail");
        return;
    }
    /* Default value of create_certificate = true, hence it should return
     * valid certificate
     */
    if (dc_output.certificate_actual_size == 0) {
        TEST_FAIL("DPE DeriveContext test: Without optional parameter should not fail");
        return;
    }
    DESTROY_SINGLE_CONTEXT(dc_output.out_ctx_handle);

    retained_rot_ctx_handle = dc_output.out_parent_handle;
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);
    test_params.is_create_certificate_missing = false;
    test_params.is_return_certificate_missing = true;
    dc_output.certificate_actual_size = 0;
    dpe_err = CALL_DERIVE_CONTEXT_WITH_TEST_PARAM(dc_input, dc_output, test_params);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveContext test: Without optional parameter should not fail");
        return;
    }
    /* Default value of return_certificate = false, hence it should NOT
     * return valid certificate
     */
    if (dc_output.certificate_actual_size != 0) {
        TEST_FAIL("DPE DeriveContext test: Without optional parameter should not fail");
        return;
    }
    DESTROY_SINGLE_CONTEXT(dc_output.out_ctx_handle);

    retained_rot_ctx_handle = dc_output.out_parent_handle;
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);
    test_params.is_return_certificate_missing = false;
    test_params.is_allow_new_context_to_export_missing = true;
    dpe_err = CALL_DERIVE_CONTEXT_WITH_TEST_PARAM(dc_input, dc_output, test_params);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveContext test: Without optional parameter should not fail");
        return;
    }
    //TODO: Side effect validation as below
    // Will need to call DeriveContext again and check if CDI cannot be exported,
    // but it also depends on few other arguments which will make this test case complex.
    DESTROY_SINGLE_CONTEXT(dc_output.out_ctx_handle);

    retained_rot_ctx_handle = dc_output.out_parent_handle;
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);
    test_params.is_allow_new_context_to_export_missing = false;
    test_params.is_export_cdi_missing = true;
    dc_output.exported_cdi_actual_size = 0;
    dpe_err = CALL_DERIVE_CONTEXT_WITH_TEST_PARAM(dc_input, dc_output, test_params);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveContext test: Without optional parameter should not fail");
        return;
    }
    /* Default value of export_cdi = false, hence it should NOT return CDI */
    if (dc_output.exported_cdi_actual_size != 0) {
        TEST_FAIL("DPE DeriveContext test: Without optional parameter should not fail");
        return;
    }
    DESTROY_SINGLE_CONTEXT(dc_output.out_ctx_handle);

    retained_rot_ctx_handle = dc_output.out_parent_handle;
    TEST_LOG("retained_rot_ctx_handle = 0x%x\r\n", retained_rot_ctx_handle);
    test_params.is_export_cdi_missing = false;
    test_params.is_retain_parent_context_missing = true;
    /* This test will create undestroyable context as default value of
     * retain_parent_context is false
     */
    dc_input.cert_id = DPE_UNDESTROYABLE_CTX_CERT_ID_5;
    dpe_err = CALL_DERIVE_CONTEXT_WITH_TEST_PARAM(dc_input, dc_output, test_params);
    if (dpe_err != DPE_NO_ERROR) {
        TEST_FAIL("DPE DeriveContext test: Without optional parameter should not fail");
        return;
    }
    /* Default value of retain_parent_context = false, hence it should NOT
     * return valid parent handle
     */
    if (dc_output.out_parent_handle != INVALID_HANDLE) {
        TEST_FAIL("DPE DeriveContext test: Without optional parameter should not fail");
        return;
    }

    ret->val = TEST_PASSED;
}
