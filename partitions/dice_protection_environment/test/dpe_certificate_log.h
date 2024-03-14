/*
 * Copyright (c) 2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __DPE_CERTIFICATE_LOG_H__
#define __DPE_CERTIFICATE_LOG_H__

#include "dpe_certificate_decode.h"
#include "qcbor/qcbor_decode.h"

#ifdef __cplusplus
extern "C" {
#endif

void print_usefulbuf(const char *indent, UsefulBufC buf);
void print_certificate(int cert_cnt, const struct certificate *cert);
void print_certificate_chain(const struct certificate_chain *cert_chain);

#ifdef __cplusplus
}
#endif

#endif /* __DPE_CERTIFICATE_LOG_H__ */
