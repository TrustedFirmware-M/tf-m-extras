/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dice_protection_environment.h"
#include "dpe_test_data.h"

#define INVALID_COMPONENT_IDX 0xFFFF

int last_retained_child_handle;

const struct dpe_derive_child_test_data_t derive_child_test_dataset_1[DERIVE_CHILD_TEST_DATA1_SIZE] = {
    {
        {
            /* Derive RSS_BL2, Caller/Parent RSS BL1_2 */
            .in_handle_comp_idx = 1,
            .retain_parent_context = false,
            .allow_child_to_derive = true,
            .create_certificate = false,
        },
        {
            .expected_child_handle_idx = 5,
            .expected_parent_handle_idx = INVALID_COMPONENT_IDX,
        }
    },
    {
        {
            /* Derive SCP_BL1 (1st child of RSS BL2) */
            .in_handle_comp_idx = 5,
            .retain_parent_context = true,
            .allow_child_to_derive = false,
            .create_certificate = false,
        },
        {
            .expected_child_handle_idx = INVALID_COMPONENT_IDX,
            .expected_parent_handle_idx = 6,
        }
    },
    {
        {
            /* Derive AP_BL1, (2nd child of RSS BL2) */
            .in_handle_comp_idx = 6,
            .retain_parent_context = true,
            .allow_child_to_derive = true,
            .create_certificate = false,
        },
        {
            .expected_child_handle_idx = 7,
            .expected_parent_handle_idx = 8,
        }
    },
    {
        {
            /* Derive RSS_S, (3rd child of RSS BL2) */
            .in_handle_comp_idx = 8,
            .retain_parent_context = true,
            .allow_child_to_derive = false,
            .create_certificate = false,
        },
        {
            .expected_child_handle_idx = INVALID_COMPONENT_IDX,
            .expected_parent_handle_idx = 9,
        }
    },
    {
        {
            /* Derive RSS_NS, (4th child of RSS BL2) */
            .in_handle_comp_idx = 9,
            .retain_parent_context = false,
            .allow_child_to_derive = false,
            .create_certificate = false,
        },
        {
            .expected_child_handle_idx = INVALID_COMPONENT_IDX,
            .expected_parent_handle_idx = INVALID_COMPONENT_IDX,
        }
    },
    {
        {
            /* Derive FW_CONFIG, (1st child of AP_BL1) */
            .in_handle_comp_idx = 7,
            .retain_parent_context = true,
            .allow_child_to_derive = false,
            .create_certificate = false,
        },
        {
            .expected_child_handle_idx = INVALID_COMPONENT_IDX,
            .expected_parent_handle_idx = 10,
        }
    },
    {
        {
            /* Derive TB_FW_CONFIG, (2nd child of AP_BL1) */
            .in_handle_comp_idx = 10,
            .retain_parent_context = true,
            .allow_child_to_derive = false,
            .create_certificate = false,
        },
        {
            .expected_child_handle_idx = INVALID_COMPONENT_IDX,
            .expected_parent_handle_idx = 11,
        }
    },
    {
        {
            /* Derive AP_BL2, (3rd child of AP_BL1) */
            .in_handle_comp_idx = 11,
            .retain_parent_context = false,
            .allow_child_to_derive = true,
            .create_certificate = false,
        },
        {
            .expected_child_handle_idx = 12,
            .expected_parent_handle_idx = INVALID_COMPONENT_IDX,
        }
    },
    {
        {
            /* Derive AP_BL31, (1st child of AP_BL2) */
            .in_handle_comp_idx = 12,
            .retain_parent_context = true,
            .allow_child_to_derive = false,
            .create_certificate = true, /* Finalise Platform layer */
        },
        {
            .expected_child_handle_idx = INVALID_COMPONENT_IDX,
            .expected_parent_handle_idx = 13,
        }
    },
    {
        {
            /* Derive AP_SPM, (2nd child of AP_BL2) */
            .in_handle_comp_idx = 13,
            .retain_parent_context = true,
            .allow_child_to_derive = false,
            .create_certificate = false,
        },
        {
            .expected_child_handle_idx = INVALID_COMPONENT_IDX,
            .expected_parent_handle_idx = 14,
        }
    },
    {
        {
            /* Derive AP_SPx, (3rd child of AP_BL2) */
            .in_handle_comp_idx = 14,
            .retain_parent_context = true,
            .allow_child_to_derive = false,
            .create_certificate = false,
        },
        {
            .expected_child_handle_idx = INVALID_COMPONENT_IDX,
            .expected_parent_handle_idx = 15,
        }
    },
    {
        {
            /* Derive AP_NS_BL, (4th child of AP_BL2) */
            .in_handle_comp_idx = 15,
            .retain_parent_context = false,
            .allow_child_to_derive = true,
            .create_certificate = false,
        },
        {
            .expected_child_handle_idx = 16,
            .expected_parent_handle_idx = INVALID_COMPONENT_IDX,
        }
    },
    {
        {
            /* Derive AP_HOST_OS, (1st child of AP_NS_BL) */
            .in_handle_comp_idx = 16,
            .retain_parent_context = true,
            .allow_child_to_derive = false,
            .create_certificate = false,
        },
        {
            .expected_child_handle_idx = INVALID_COMPONENT_IDX,
            .expected_parent_handle_idx = 17,
        }
    },
    {
        {
            /* Derive AP_PVM_FW, (2nd child of AP_NS_BL) */
            .in_handle_comp_idx = 17,
            .retain_parent_context = false,
            .allow_child_to_derive = true,
            .create_certificate = true, /* Finalise Secure World & Hypervisor layer */
        },
        {
            .expected_child_handle_idx = 18,
            .expected_parent_handle_idx = INVALID_COMPONENT_IDX,
        }
    },
    {
        {
            /* Derive AP_GUEST_KERNEL_1, (1st child of AP_PVM_FW) */
            .in_handle_comp_idx = 18,
            .retain_parent_context = true,
            .allow_child_to_derive = true,
            .create_certificate = false,
        },
        {
            .expected_child_handle_idx = 19,
            .expected_parent_handle_idx = 20,
        }
    },
    {
        {
            /* Derive AP_GUEST_KERNEL_2, (2nd child of AP_PVM_FW) */
            .in_handle_comp_idx = 20,
            .retain_parent_context = true,
            .allow_child_to_derive = true,
            .create_certificate = false,
        },
        {
            .expected_child_handle_idx = 21,
            .expected_parent_handle_idx = 22,
        }
    },
};

/* Below dataset is used for CertifyKey command test */
const struct dpe_derive_child_test_data_t derive_child_test_dataset_2[DERIVE_CHILD_TEST_DATA2_SIZE] = {
    {
        {
            /* Derive RSS_BL2, Caller/Parent RSS BL1_2 */
            .in_handle_comp_idx = 1,
            .retain_parent_context = true,
            .allow_child_to_derive = true,
            .create_certificate = false,
        },
        {
            .expected_child_handle_idx = 2,
            .expected_parent_handle_idx = 3,
        }
    },
    {
        {
            /* Derive SCP_BL1 (1st child of RSS BL2) */
            .in_handle_comp_idx = 2,
            .retain_parent_context = true,
            .allow_child_to_derive = true,
            .create_certificate = false,
        },
        {
            .expected_child_handle_idx = 4,
            .expected_parent_handle_idx = 5,
        }
    },
    {
        {
            /* Derive AP_BL1, (2nd and final child of RSS BL2) */
            .in_handle_comp_idx = 5,
            .retain_parent_context = true,
            .allow_child_to_derive = true,
            .create_certificate = true, /* Finalise Platform layer */
        },
        {
            .expected_child_handle_idx = 6,
            .expected_parent_handle_idx = 7,
        }
    },
};

/* Below dataset is used for CertifyKey command test */
const struct dpe_derive_child_test_data_t derive_child_test_dataset_3 = {
    {
        /* Derive RSS_BL2, Caller/Parent RSS BL1_2 */
        .in_handle_comp_idx = 1,
        .retain_parent_context = true,
        .allow_child_to_derive = true,
        .create_certificate = false,
    },
    {
        .expected_child_handle_idx = 2,
        .expected_parent_handle_idx = 3,
    }
};
