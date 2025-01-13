/*
 * Copyright (c) 2024-2025, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __DPE_CERTIFICATE_DECODE_H__
#define __DPE_CERTIFICATE_DECODE_H__

#include <stdbool.h>

#include "qcbor/UsefulBuf.h"
#include "t_cose/t_cose_key.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_SW_COMPONENT_NUM    3
#define MAX_CERT_NUM            3

struct component {
    UsefulBufC code_hash;
    UsefulBufC authority_hash;
    UsefulBufC code_descriptor;
    /* TODO: Add the missing ones */
};

struct cdi_export {
   bool presence;
   bool value;
};

struct certificate {
    /* Array elements in the COSE_Sign1 CBOR object */
    UsefulBufC protected_header;  /* Byte string */

    /* Unprotected header is usually empty */

    /* Claims within the payload */
    UsefulBufC pub_key;           /* Byte string wrapped COSE_Key */
    UsefulBufC issuer;            /* Text */
    UsefulBufC subject;           /* Text */
    UsefulBufC key_usage;         /* Byte string */
    UsefulBufC external_label;    /* Text */
    struct cdi_export cdi_export; /* Boolean */

    /* Number of SW components contributes to this certificate */
    unsigned int component_cnt;
    struct component component_arr[MAX_SW_COMPONENT_NUM];

    UsefulBufC signature;        /* Byte string */
};

struct certificate_chain {
    UsefulBufC root_pub_key;
    unsigned int cert_cnt;
    struct certificate cert_arr[MAX_CERT_NUM];
};

int verify_certificate(UsefulBufC cert_buf,
                       struct t_cose_key pub_key_id,
                       struct certificate *cert);

int verify_certificate_chain(UsefulBufC cert_chain_buf,
                             struct certificate_chain *cert_chain,
                             struct t_cose_key *last_pub_key_id);

int unregister_pub_key(struct t_cose_key pub_key_id);

int compare_certificate_chains(struct certificate_chain *decoded_chain_1,
                               struct certificate_chain *decoded_chain_2);

int compare_certificate_chains_light(struct certificate_chain *decoded_chain_1,
                                     struct certificate_chain *decoded_chain_2);

#ifdef __cplusplus
}
#endif

#endif /* __DPE_CERTIFICATE_DECODE_H__ */
