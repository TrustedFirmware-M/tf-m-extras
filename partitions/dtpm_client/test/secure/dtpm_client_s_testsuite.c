/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 */

#include <endian.h>
#include <stddef.h>

#include "dtpm_client_api.h"
#include "tpm2.h"
#include "dtpm_client_partition_hal.h"

#include "tfm_utils.h"

#include "test_framework_helpers.h"

#define DEBUG_PCR_NUMBER 16 /* Debug PCR */

#ifndef TPM_INSTANCE_ID
#define TPM_INSTANCE_ID 0
#endif

static const struct tpm_spi_plat *tpm_spi_plat;
static struct tpm_timeout_ops tpm_timeout_ops;

/* 0xf24e63d9d0b181578f1f020dbec85d2df795567599a6695b1c72197e3d375f13 */
static const uint8_t digest_256[] = {
    0xf2, 0x4e, 0x63, 0xd9, 0xd0, 0xb1, 0x81, 0x57,
    0x8f, 0x1f, 0x02, 0x0d, 0xbe, 0xc8, 0x5d, 0x2d,
    0xf7, 0x95, 0x56, 0x75, 0x99, 0xa6, 0x69, 0x5b,
    0x1c, 0x72, 0x19, 0x7e, 0x3d, 0x37, 0x5f, 0x13
};

/*SHA256(0000000000000000000000000000000000000000000000000000000000000000 ||
 * f24e63d9d0b181578f1f020dbec85d2df795567599a6695b1c72197e3d375f13) =
 * a52871f78f0f77eb69c17c7daaf3c58e6177c91bb8ee825fd1be8816d0869fc3
 */
const uint8_t expected_data[] = {
    0xa5, 0x28, 0x71, 0xf7, 0x8f, 0x0f, 0x77, 0xeb,
    0x69, 0xc1, 0x7c, 0x7d, 0xaa, 0xf3, 0xc5, 0x8e,
    0x61, 0x77, 0xc9, 0x1b, 0xb8, 0xee, 0x82, 0x5f,
    0xd1, 0xbe, 0x88, 0x16, 0xd0, 0x86, 0x9f, 0xc3
};

/*
 * Test function to read out value from a PCR
 */
static int dtpm_client_read(uint8_t pcr_index, uint8_t *pcr_read_response,
                            size_t pcr_read_response_len)
{
    int status;
    const struct tpm_chip_timeouts tpm_timeouts = {
            .msec_a = 750,
            .msec_b = 2000,
            .msec_c = 200,
            .msec_d = 30,
    };

    const struct tpm_chip_data tpm_chip_data = {
        .locality = 0,
        .timeouts = &tpm_timeouts,
    };

    status = tpm_interface_init(tpm_spi_plat, &tpm_timeout_ops, &tpm_chip_data, 0);
    if (status) {
        return status;
    }

    status = tpm_pcr_read_single(&tpm_chip_data, pcr_index, TPM_ALG_SHA256,
                                 pcr_read_response, pcr_read_response_len);

    tpm_interface_close(&tpm_chip_data, 0);

    return status;
}

void pcr_extend_test_001(struct test_result_t *ret)
{
    psa_status_t status;
    uint8_t pcr_read_response[MAX_DIGEST_SIZE];

    if (tpm_plat_get_tpm_platform_config(&tpm_timeout_ops, &tpm_spi_plat, TPM_INSTANCE_ID)) {
       TEST_FAIL("Failed to get platform config");
       return;
    }

    status = tfm_dtpm_client_extend(DEBUG_PCR_NUMBER, TPM_ALG_SHA256, digest_256, sizeof(digest_256));
    if (status != PSA_SUCCESS) {
       TEST_FAIL("Failed to extend PCR register");
       return;
    }

    status = dtpm_client_read(DEBUG_PCR_NUMBER, &pcr_read_response, ARRAY_SIZE(pcr_read_response));
    if (status != TPM_SUCCESS) {
            TEST_FAIL("Failed to read extended value from TPM");
    }

    for (int i = 0; i < ARRAY_SIZE(expected_data); i++) {
        if (pcr_read_response[i] != expected_data[i]) {
            TEST_FAIL("TPM extend operation returned incorrect value");
            return;
        }
    }

    ret->val = TEST_PASSED;
}

static struct test_t tfm_dtpm_client_s_tests[] = {
    {&pcr_extend_test_001, "TFM_S_DTM_CLIENT_TEST_1001", "dTPM Client Secure extend test"},
};

void register_testsuite_extra_s_interface(struct test_suite_t *p_test_suite)
{
    /* Add platform init code here. */

    uint32_t list_size;

    list_size = (sizeof(tfm_dtpm_client_s_tests) /
                 sizeof(tfm_dtpm_client_s_tests[0]));

    set_testsuite("Extra Secure interface tests"
                  "(TFM_S_DTPM_CLIENT_1XXX)",
                  tfm_dtpm_client_s_tests, list_size, p_test_suite);
}
