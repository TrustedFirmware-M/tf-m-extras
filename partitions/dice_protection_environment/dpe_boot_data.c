/*
 * Copyright (c) 2023-2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dpe_boot_data.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "boot_hal.h"
#include "boot_measurement.h"
#include "dice_protection_environment.h"
#include "dpe_context_mngr.h"
#include "platform_locality.h"
#include "psa/lifecycle.h"
#include "psa_manifest/pid.h"
#include "service_api.h"
#include "tfm_boot_status.h"

#define DPE_PLATFORM_CERT_ID 0x200

/* Maximum measurement size is size of SHA-512 hash */
#define MEASUREMENT_VALUE_MAX_SIZE 64

/* Size of 1 complete measurement (value + metadata) in TLV format. */
#define SHARED_BOOT_MEASUREMENT_SIZE \
    ((2 * SHARED_DATA_ENTRY_HEADER_SIZE) \
     + sizeof(struct boot_measurement_metadata) \
     + MEASUREMENT_VALUE_MAX_SIZE)

/* 2 measurements from the BL1 stages and 1 measurement per image from BL2. */
#define MAX_SHARED_BOOT_DATA_LENGTH \
    ((2 + MCUBOOT_IMAGE_NUMBER) * SHARED_BOOT_MEASUREMENT_SIZE)

/**
 * \struct boot_measurement_data
 *
 * \brief Contains all the measurement and related metadata (from BL1_x and BL2).
 *
 * \details This is a redefinition of \ref tfm_boot_data to allocate the
 *          appropriate, service dependent size of \ref boot_data.
 */
struct boot_measurement_data {
    struct shared_data_tlv_header header;
    uint8_t data[MAX_SHARED_BOOT_DATA_LENGTH];
};

/**
 * \var boot_measurements
 *
 * \brief Store the boot measurements in the service's memory.
 *
 * \details Boot measurements come from the BL1 and BL2 boot stages and stored
 *          on a memory area which is shared between the bootloaders and SPM.
 *          SPM provides the \ref tfm_core_get_boot_data() API to retrieve
 *          the service related data from shared area.
 */
__attribute__ ((aligned(4)))
static struct boot_measurement_data boot_measurements;

/**
 * \brief Get the current DICE mode based on HW state.
 *
 * \return DICE mode.
 */
static DiceMode get_dice_mode(void)
{
    uint32_t psa_lcs;

    /* get PSA RoT life cycle state */
    psa_lcs = psa_rot_lifecycle_state();

    /* FIXME consider DCU state as well */
    switch (psa_lcs) {
    case PSA_LIFECYCLE_SECURED:
        return kDiceModeNormal;
    case PSA_LIFECYCLE_DECOMMISSIONED:
        return kDiceModeMaintenance;
    default:
        return kDiceModeNotInitialized;
    }
}

/**
 * \brief Convert boot measurement data to DICE input values.
 *
 * \param[in]  metadata         Boot measurement metadata.
 * \param[in]  measurement      Boot measurement.
 * \param[in]  measurement_len  Length of measurement input.
 * \param[out] dice_inputs      DICE input values.
 *
 * \return Returns 0 on success, -1 on failure.
 */
static int measurement_to_dice_inputs(const struct boot_measurement_metadata *metadata,
                                      const uint8_t *measurement,
                                      size_t measurement_len,
                                      DiceInputValues *dice_inputs)
{
    uint8_t *cfg_p;

    if (measurement_len > sizeof(dice_inputs->code_hash) ||
        metadata->signer_id_size > sizeof(metadata->signer_id) ||
        metadata->signer_id_size > sizeof(dice_inputs->authority_hash)) {
        return -1;
    }

    /* Zero DICE inputs to ensure unused values are zero */
    memset(dice_inputs, 0, sizeof(*dice_inputs));

    /* Code hash */
    memcpy(dice_inputs->code_hash, measurement, measurement_len);

    /* Code descriptor */
    dice_inputs->code_descriptor = (uint8_t *)&metadata->measurement_type;
    dice_inputs->code_descriptor_size = sizeof(metadata->measurement_type);

    /* Config value */
    dice_inputs->config_type = kDiceConfigTypeInline;
    cfg_p = dice_inputs->config_value;

    memcpy(cfg_p, &metadata->sw_version.build_num,
           sizeof(metadata->sw_version.build_num));
    cfg_p += sizeof(metadata->sw_version.build_num);

    memcpy(cfg_p, &metadata->sw_version.revision,
           sizeof(metadata->sw_version.revision));
    cfg_p += sizeof(metadata->sw_version.revision);

    memcpy(cfg_p, &metadata->sw_version.minor,
           sizeof(metadata->sw_version.minor));
    cfg_p += sizeof(metadata->sw_version.minor);

    memcpy(cfg_p, &metadata->sw_version.major,
           sizeof(metadata->sw_version.major));

    /* Authority hash */
    memcpy(dice_inputs->authority_hash, metadata->signer_id,
           metadata->signer_id_size);

    /* Mode */
    dice_inputs->mode = get_dice_mode();

    return 0;
}

/**
 * \brief Function pointer type that indicates whether slot meets condition.
 */
typedef bool (*slot_cond_t)(uint8_t slot);

/**
 * \brief Iteratively get measurements whose slot values meet the condition of
 *        the supplied condition function.
 *
 * \param[in]     slot_cond    Slot condition function.
 * \param[in,out] itr          Pointer to iterator. If the pointed-to value is
 *                             NULL then the function searches from the
 *                             beginning of the data area. The iterator value is
 *                             updated by the function and should be supplied to
 *                             subsequent calls to continue the search.
 * \param[out]    dice_inputs  DICE input values.
 *
 * \return Returns integer error code.
 * \retval -1  Failure.
 * \retval  0  Success, reached end of data area without finding a component.
 * \retval  1  Success, component found.
 */
static int get_measurement_for_slot_cond(slot_cond_t slot_cond,
                                         void **itr,
                                         DiceInputValues *dice_inputs)
{
    struct boot_measurement_metadata *metadata;
    uint8_t *measurement;
    size_t measurement_len;
    struct shared_data_tlv_entry tlv_entry;
    uint8_t *tlv_curr;
    uint8_t *tlv_end;
    uint8_t slot;
    uint8_t claim;

    if (boot_measurements.header.tlv_magic != SHARED_DATA_TLV_INFO_MAGIC) {
        /* Boot measurement information is malformed. */
        return -1;
    }

    /* Get the boundaries of TLV section where to lookup. */
    tlv_curr = (*itr == NULL) ? boot_measurements.data : (uint8_t *)*itr;
    tlv_end = (uint8_t *)&boot_measurements
              + boot_measurements.header.tlv_tot_len;

    while (tlv_curr < tlv_end) {
        /* Copy TLV entry header - the measurement metadata must come first. */
        memcpy(&tlv_entry, tlv_curr, SHARED_DATA_ENTRY_HEADER_SIZE);
        slot = GET_MBS_SLOT(tlv_entry.tlv_type);

        if ((*slot_cond)(slot)) {
            if ((GET_MBS_CLAIM(tlv_entry.tlv_type) != SW_MEASURE_METADATA) ||
                (tlv_entry.tlv_len != sizeof(struct boot_measurement_metadata))) {
                /* Boot measurement information is malformed. */
                return -1;
            }

            metadata = (struct boot_measurement_metadata *)
                       (tlv_curr + SHARED_DATA_ENTRY_HEADER_SIZE);

            /* Copy next TLV entry header - it must belong to the measurement. */
            tlv_curr += (SHARED_DATA_ENTRY_HEADER_SIZE + tlv_entry.tlv_len);
            memcpy(&tlv_entry, tlv_curr, SHARED_DATA_ENTRY_HEADER_SIZE);
            claim = GET_MBS_CLAIM(tlv_entry.tlv_type);

            if ((claim != SW_MEASURE_VALUE) &&
                (claim != SW_MEASURE_VALUE_NON_EXTENDABLE)) {
                /* Boot measurement information is malformed. */
                return -1;
            }

            measurement = tlv_curr + SHARED_DATA_ENTRY_HEADER_SIZE;
            measurement_len = tlv_entry.tlv_len;

            if (measurement_to_dice_inputs(metadata, measurement,
                                           measurement_len, dice_inputs) != 0) {
                return -1;
            }

            /* Set iterator to point to next TLV entry */
            *itr = tlv_curr + SHARED_DATA_ENTRY_HEADER_SIZE + tlv_entry.tlv_len;

            return 1;
        }

        /* Move to the next TLV entry. */
        tlv_curr += (SHARED_DATA_ENTRY_HEADER_SIZE + tlv_entry.tlv_len);
    }

    return 0;
}

dpe_error_t initialise_boot_data(void)
{
    psa_status_t status;

    /* Collect the measurements from the shared data area and store them. */
    status = tfm_core_get_boot_data(TLV_MAJOR_MBS,
                                    (struct tfm_boot_data *)&boot_measurements,
                                    sizeof(boot_measurements));
    if (status != PSA_SUCCESS) {
        return DPE_INTERNAL_ERROR;
    }

    return DPE_NO_ERROR;
}

static bool bl1_2_cond(uint8_t slot)
{
    return slot == BOOT_MEASUREMENT_SLOT_BL1_2;
}

static bool bl2_cond(uint8_t slot)
{
    return slot == BOOT_MEASUREMENT_SLOT_BL2;
}

static bool plat_cond(uint8_t slot)
{
    return slot >= BOOT_MEASUREMENT_SLOT_RT_0 &&
           slot <= BOOT_MEASUREMENT_SLOT_MAX &&
           slot != BOOT_MEASUREMENT_SLOT_RT_2;
}

static bool ap_cond(uint8_t slot)
{
    return slot == BOOT_MEASUREMENT_SLOT_RT_2; /* FIXME: This may vary */
}

dpe_error_t derive_boot_data_contexts(int rot_ctx_handle,
                                      int *new_ctx_handle)
{
    int ret;
    dpe_error_t err;
    void *itr;
    DiceInputValues dice_inputs;
    int plat_ctx_handle;
    int invalid_ctx_handle;

    /* Only the BL1_2 measurement is included in the RoT certificate */
    itr = NULL;
    ret = get_measurement_for_slot_cond(&bl1_2_cond, &itr, &dice_inputs);
    if (ret != 1) {
        /* RoT certificate measurement is either malformed or missing, fatal error */
        return DPE_INTERNAL_ERROR;
    }

    /* Derive RoT certificate */
    err = derive_context_request(rot_ctx_handle,
                                 DPE_ROT_CERT_ID, /* cert_id */
                                 false, /* retain_parent_context */
                                 true, /* allow_new_context_to_derive */
                                 true, /* create certificate */
                                 &dice_inputs,
                                 TFM_SP_DPE, /* client_id */
                                 LOCALITY_RSE_S, /* target_locality */
                                 false, /* return_certificate */
                                 true, /* allow_new_context_to_export */
                                 false, /* export_cdi */
                                 &plat_ctx_handle, /* new_ctx_handle */
                                 &invalid_ctx_handle, /* new_parent_ctx_handle */
                                 NULL, /* new_certificate_buf */
                                 0, /* new_certificate_buf_size */
                                 NULL, /* new_certificate_actual_size */
                                 NULL, /* exported_cdi_buf */
                                 0, /* exported_cdi_buf_size */
                                 NULL); /* exported_cdi_actual_size */
    if (err != DPE_NO_ERROR) {
        return err;
    }

    /* Get BL2 measurement */
    itr = NULL;
    ret = get_measurement_for_slot_cond(&bl2_cond, &itr, &dice_inputs);
    if (ret != 1) {
        /* BL2 measurement is either malformed or missing, fatal error */
        return DPE_INTERNAL_ERROR;
    }

    /* Derive BL2 context */
    err = derive_context_request(plat_ctx_handle,
                                 DPE_PLATFORM_CERT_ID, /* cert_id */
                                 false, /* close parent context */
                                 true, /* allow BL2 to derive further */
                                 false, /* create_certificate */
                                 &dice_inputs,
                                 TFM_SP_DPE, /* client_id */
                                 LOCALITY_RSE_S, /* target_locality */
                                 false, /* return_certificate */
                                 true, /* allow_new_context_to_export */
                                 false, /* export_cdi */
                                 &plat_ctx_handle, /* new_ctx_handle */
                                 &invalid_ctx_handle, /* new_parent_ctx_handle */
                                 NULL, /* new_certificate_buf */
                                 0, /* new_certificate_buf_size */
                                 NULL, /* new_certificate_actual_size */
                                 NULL, /* exported_cdi_buf */
                                 0, /* exported_cdi_buf_size */
                                 NULL); /* exported_cdi_actual_size */
    if (err != DPE_NO_ERROR) {
        return err;
    }

    /* Get measurements for the rest of platform certificate, except AP */
    itr = NULL;
    while ((ret = get_measurement_for_slot_cond(&plat_cond, &itr,
                                                &dice_inputs)) == 1) {
        /* Derive rest of platform contexts from retained BL2 context */
        err = derive_context_request(plat_ctx_handle,
                                     DPE_CERT_ID_SAME_AS_PARENT, /* cert_id */
                                     true, /* retain parent context */
                                     false, /* do not allow derived context to derive */
                                     false, /* create_certificate */
                                     &dice_inputs,
                                     TFM_SP_DPE, /* client_id */
                                     LOCALITY_RSE_S, /* target_locality */
                                     false, /* return_certificate */
                                     true, /* allow_new_context_to_export */
                                     false, /* export_cdi */
                                     &invalid_ctx_handle, /* new_ctx_handle */
                                     &plat_ctx_handle, /* new_parent_ctx_handle */
                                     NULL, /* new_certificate_buf */
                                     0, /* new_certificate_buf_size */
                                     NULL, /* new_certificate_actual_size */
                                     NULL, /* exported_cdi_buf */
                                     0, /* exported_cdi_buf_size */
                                     NULL); /* exported_cdi_actual_size */

        if (err != DPE_NO_ERROR) {
            return err;
        }
    }

    /* Check termination was due to reaching end of boot data area */
    if (ret != 0) {
        return DPE_INTERNAL_ERROR;
    }

    /* Get AP measurement */
    itr = NULL;
    ret = get_measurement_for_slot_cond(&ap_cond, &itr, &dice_inputs);
    if (ret != 1) {
        /* AP measurement is either malformed or missing, fatal error */
        return DPE_INTERNAL_ERROR;
    }

    /* Derive AP context, with the new derived context handle returned to the
     * caller in the new_ctx_handle output parameter.
     */
    return derive_context_request(plat_ctx_handle,
                                  DPE_CERT_ID_SAME_AS_PARENT, /* cert_id */
                                  false, /* close parent context */
                                  true, /* allow AP to derive */
                                  true, /* create_certificate */
                                  &dice_inputs,
                                  TFM_SP_DPE, /* client_id */
                                  LOCALITY_AP_S, /* target_locality */
                                  false, /* return_certificate */
                                  true, /* allow_new_context_to_export */
                                  false, /* export_cdi */
                                  new_ctx_handle, /* new_ctx_handle */
                                  &invalid_ctx_handle, /* new_parent_ctx_handle */
                                  NULL, /* new_certificate_buf */
                                  0, /* new_certificate_buf_size */
                                  NULL, /* new_certificate_actual_size */
                                  NULL, /* exported_cdi_buf */
                                  0, /* exported_cdi_buf_size */
                                  NULL); /* exported_cdi_actual_size */

}
