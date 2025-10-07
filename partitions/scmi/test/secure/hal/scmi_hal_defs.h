/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 */

#ifndef __SCMI_HAL_DEFS_H__
#define __SCMI_HAL_DEFS_H__

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

extern char test_shared_mem[];
extern volatile bool test_doorbell_sender;
extern volatile bool test_doorbell_receiver;

/* Base address and size of shared memory with SCP for SCMI transport */
#define SCP_SHARED_MEMORY_BASE (&test_shared_mem)
#define SCP_SHARED_MEMORY_SIZE 128U

#define SCP_SHARED_MEMORY_RECEIVER_BASE (&test_shared_mem[SCP_SHARED_MEMORY_SIZE / 2])

#ifdef __cplusplus
}
#endif

#endif /* __SCMI_HAL_DEFS_H__ */
