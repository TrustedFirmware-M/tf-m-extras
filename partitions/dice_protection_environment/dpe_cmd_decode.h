/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __DPE_CMD_DECODE_H__
#define __DPE_CMD_DECODE_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Call the DPE service with a CBOR-encoded DPE command.
 *
 * \param[in]     client_id        Identifier of the client calling the service.
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
int32_t dpe_command_decode(int32_t client_id,
                          const char *cmd_input, size_t cmd_input_size,
                          char *cmd_output, size_t *cmd_output_size);

#ifdef __cplusplus
}
#endif

#endif /* __DPE_CMD_DECODE_H__ */
