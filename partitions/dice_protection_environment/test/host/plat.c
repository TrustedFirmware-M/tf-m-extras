/*
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdio.h>

#include "dpe_plat.h"
#include "tfm_log_unpriv.h"

extern psa_key_id_t rot_cdi_id;
extern psa_key_id_t root_attest_key_id;

psa_key_id_t dpe_plat_get_rot_cdi_key_id(void)
{
    return rot_cdi_id;
}

psa_key_id_t dpe_plat_get_root_attest_key_id(void)
{
    return root_attest_key_id;
}


int dpe_plat_share_context_with_ap(int ctx_handle)
{
    return 0;
}


int32_t dpe_plat_get_client_locality(int32_t client_id)
{
    return 0;
}
