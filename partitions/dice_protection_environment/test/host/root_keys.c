/*
 * Copyright (c) 2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "psa/crypto.h"

/*
 * The DPE implementation assumes that the runtime has no access to the UDS and
 * a previous boot stage already done the RoT CDI derivation from the UDS.
 * Therefore when the RoT certificate is created the RoT CDI derivation step is
 * skipped. The RoT CDI is assumed to be already known by the Crypto service.
 * It can be referenced by a handle: rot_cdi_id.
 */
psa_key_id_t rot_cdi_id = PSA_KEY_ID_NULL;

/*
 * Use this hard coded data as the RoT CDI. In normal operation this value is
 * derived by BL1_1.
 */
static const char rot_cdi[] = {
    0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
    0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
    0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
    0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5, 0xA5,
};

/* In normal operation this is done by Crypto service init */
int register_rot_cdi(void)
{
    psa_status_t status;
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_algorithm_t algorithm = PSA_ALG_HKDF(PSA_ALG_SHA_256);

    /* Setup the key policy */
    psa_set_key_bits(&attr, 256);
    psa_set_key_algorithm(&attr, algorithm);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);

    status = psa_import_key(&attr, rot_cdi, sizeof(rot_cdi), &rot_cdi_id);
    if (status != PSA_SUCCESS) {
        return status;
    }

    return PSA_SUCCESS;
}

psa_key_id_t root_attest_key_id = PSA_KEY_ID_NULL;

/* The RoT certificate is signed by the root attestation key. */
static const char root_attest_key[] = {
    0xA9, 0xB4, 0x54, 0xB2, 0x6D, 0x6F, 0x90, 0xA4,
    0xEA, 0x31, 0x19, 0x35, 0x64, 0xCB, 0xA9, 0x1F,
    0xEC, 0x6F, 0x9A, 0x00, 0x2A, 0x7D, 0xC0, 0x50,
    0x4B, 0x92, 0xA1, 0x93, 0x71, 0x34, 0x58, 0x5F,
};

/* In normal operation this is done by Crypto service init */
int register_root_attest_key(void)
{
    psa_status_t status;
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_algorithm_t algorithm = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
    psa_key_type_t type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);

    /* Setup the key policy */
    psa_set_key_type(&attr, type);
    psa_set_key_algorithm(&attr, algorithm);
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_EXPORT);

    status = psa_import_key(&attr, root_attest_key, sizeof(root_attest_key),
                            &root_attest_key_id);
    if (status != PSA_SUCCESS) {
        return status;
    }

    return PSA_SUCCESS;
}
