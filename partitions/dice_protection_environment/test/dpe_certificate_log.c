/*
 * Copyright (c) 2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dpe_certificate_decode.h"
#include "dpe_certificate_log.h"
#include "test_log.h"

/* Functions here are not static on purpose:
 *  - print_certificate() can be used in a DeriveContext() or
 *    CertifyKey() call.
 *  - print_usefulbuf() can be a handy debug utility in the
 *    entire DPE test code.
 */
void print_usefulbuf(const char *indent, UsefulBufC buf)
{
     size_t i;
     const uint8_t *array = (uint8_t *)buf.ptr;

    if (array != NULL) {
        for (i = 0; i < buf.len; ++i) {
            if ((i & 0xF) == 0) {
                TEST_LOG("\r\n%s", indent);
            }
            if (array[i] < 0x10) {
                TEST_LOG(" 0%x", array[i]);
            } else {
                TEST_LOG(" %x", array[i]);
            }
        }
    }
    TEST_LOG("\r\n");
    TEST_LOG("\r\n");
}

void print_certificate(int cert_cnt, const struct certificate *cert)
{
    int i;
    TEST_LOG("===================================================\r\n");
    TEST_LOG("\r\n");
    TEST_LOG("Certificate(%d):\r\n", cert_cnt);
    TEST_LOG("    - Protected header:");
    print_usefulbuf("      ", cert->protected_header);
    TEST_LOG("    - SW component array(%d):\r\n", cert->component_cnt);
    for (i = 0; i < cert->component_cnt; ++i) {
        TEST_LOG("        - Code hash(%d):", i);
        print_usefulbuf("          ", cert->component_arr[i].code_hash);
        TEST_LOG("        - Code authority hash(%d):", i);
        print_usefulbuf("          ", cert->component_arr[i].authority_hash);
    }
    TEST_LOG("    - Public key (COSE_Key):");
    print_usefulbuf("      ", cert->pub_key);
    TEST_LOG("    - Signature:");
    print_usefulbuf("      ", cert->signature);
}

void print_certificate_chain(const struct certificate_chain *cert_chain)
{
    int i;

    TEST_LOG("\r\n");
    TEST_LOG("============= Start Certificate Chain =============\r\n");
    TEST_LOG("\r\n");
    TEST_LOG("Root Public Key (COSE_Key):");
    print_usefulbuf("   ", cert_chain->root_pub_key);

    for (i = 0; i < cert_chain->cert_cnt; ++i) {
        print_certificate(i, &cert_chain->cert_arr[i]);
    }

    TEST_LOG("============ End of Certificate Chain =============\r\n");
    TEST_LOG("\r\n");
}
