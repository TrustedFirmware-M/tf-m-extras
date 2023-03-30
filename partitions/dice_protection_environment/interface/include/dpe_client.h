/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

/* DICE Protection Environment (DPE) Client API */

#ifndef __DPE_CLIENT_H__
#define __DPE_CLIENT_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CBOR labels as defined in the DICE Protection Environment specification */
enum dpe_command_id_t {
    DPE_GET_PROFILE = 1,
    DPE_OPEN_SESSION = 2,
    DPE_CLOSE_SESSION = 3,
    DPE_SYNC_SESSION = 4,
    DPE_EXPORT_SESSION = 5,
    DPE_IMPORT_SESSION = 6,
    DPE_INITIALIZE_CONTEXT = 7,
    DPE_DERIVE_CHILD = 8,
    DPE_CERTIFY_KEY = 9,
    DPE_SIGN = 10,
    DPE_SEAL = 11,
    DPE_UNSEAL = 12,
    DPE_DERIVE_SEALING_PUBLIC_KEY = 13,
    DPE_ROTATE_CONTEXT_HANDLE = 14,
    DPE_DESTROY_CONTEXT = 15,
};

enum dice_input_labels_t {
    DICE_CODE_HASH = 1,
    DICE_CODE_DESCRIPTOR = 2,
    DICE_CONFIG_TYPE = 3,
    DICE_CONFIG_VALUE = 4,
    DICE_CONFIG_DESCRIPTOR = 5,
    DICE_AUTHORITY_HASH = 6,
    DICE_AUTHORITY_DESCRIPTOR = 7,
    DICE_MODE = 8,
    DICE_HIDDEN = 9,
};

enum dpe_derive_child_input_labels_t {
    DPE_DERIVE_CHILD_CONTEXT_HANDLE = 1,
    DPE_DERIVE_CHILD_RETAIN_PARENT_CONTEXT = 2,
    DPE_DERIVE_CHILD_ALLOW_CHILD_TO_DERIVE = 3,
    DPE_DERIVE_CHILD_CREATE_CERTIFICATE = 4,
    DPE_DERIVE_CHILD_NEW_SESSION_INITIATOR_HANDSHAKE = 5,
    DPE_DERIVE_CHILD_NEW_SESSION_IS_MIGRATABLE = 6,
    DPE_DERIVE_CHILD_INPUT_DATA = 7,
    DPE_DERIVE_CHILD_INTERNAL_INPUTS = 8,
};

enum dpe_derive_child_output_labels_t {
    DPE_DERIVE_CHILD_NEW_CONTEXT_HANDLE = 1,
    DPE_DERIVE_CHILD_NEW_SESSION_RESPONDER_HANDSHAKE = 2,
    DPE_DERIVE_CHILD_PARENT_CONTEXT_HANDLE = 3,
};

enum dpe_certify_key_input_labels_t {
    DPE_CERTIFY_KEY_CONTEXT_HANDLE = 1,
    DPE_CERTIFY_KEY_RETAIN_CONTEXT = 2,
    DPE_CERTIFY_KEY_PUBLIC_KEY = 3,
    DPE_CERTIFY_KEY_LABEL = 4,
    DPE_CERTIFY_KEY_POLICIES = 5,
};

enum dpe_certify_key_output_labels_t {
    DPE_CERTIFY_KEY_CERTIFICATE_CHAIN = 1,
    DPE_CERTIFY_KEY_DERIVED_PUBLIC_KEY = 2,
    DPE_CERTIFY_KEY_NEW_CONTEXT_HANDLE = 3,
};

/**
 * \brief Dispatch a call to the DPE service with a CBOR-encoded DPE command.
 *
 * \param[in]     cmd_input        Pointer to buffer containing the input
 *                                 CBOR-encoded DPE command.
 * \param[in]     cmd_input_size   Size of the input command, in bytes.
 * \param[out]    cmd_output       Pointer to buffer to write the CBOR-encoded
 *                                 DPE command output.
 * \param[in,out] cmd_output_size  On input, size of the command output buffer
 *                                 in bytes. On successful return, size of the
 *                                 response written to the buffer.
 *
 * \note The cmd_input and cmd_output memory areas may overlap.
 *
 * \return Returns 0 if call succeeded and cmd_output contains a valid response
 *         and returns less than 0 otherwise.
 */
int32_t dpe_client_call(const char *cmd_input, size_t cmd_input_size,
                        char *cmd_output, size_t *cmd_output_size);

#ifdef __cplusplus
}
#endif

#endif /* __DPE_CLIENT_H__ */
