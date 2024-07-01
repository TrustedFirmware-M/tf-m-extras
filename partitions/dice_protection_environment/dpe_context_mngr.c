/*
 * Copyright (c) 2023-2024, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dpe_context_mngr.h"
#include <assert.h>
#include <string.h>
#include "array.h"
#include "dice_protection_environment.h"
#include "dpe_certificate.h"
#include "dpe_client.h"
#include "dpe_crypto_interface.h"
#include "dpe_log.h"
#include "dpe_plat.h"
#include "psa/crypto.h"

#define CONTEXT_DATA_MAX_SIZE sizeof(struct component_context_data_t)

static struct component_context_t component_ctx_array[MAX_NUM_OF_COMPONENTS];
static struct cert_context_t cert_ctx_array[MAX_NUM_OF_CERTIFICATES];

static dpe_error_t store_linked_component(struct cert_context_t *cert_ctx,
                                          int component_idx)
{
    if (cert_ctx->linked_components.count >=
            ARRAY_SIZE(cert_ctx->linked_components.idx)) {
        /* linked_components.idx[] is full */
        return DPE_INSUFFICIENT_MEMORY;
    }

    cert_ctx->linked_components.idx[cert_ctx->linked_components.count] = component_idx;
    cert_ctx->linked_components.count++;

    return DPE_NO_ERROR;
}

static void remove_linked_component(struct cert_context_t *cert_ctx,
                                    int component_idx)
{
    int i, pos;

    /* Find the position of the input component */
    for (i = 0; i < ARRAY_SIZE(cert_ctx->linked_components.idx); i++) {
        if (cert_ctx->linked_components.idx[i] == component_idx) {
            pos = i;
            break;
        }
    }

    assert(i < ARRAY_SIZE(cert_ctx->linked_components.idx));

    /* Left shift remaining elements by 1 from current position */
    for(i = pos; i < ARRAY_SIZE(cert_ctx->linked_components.idx) - 1; i++) {
        cert_ctx->linked_components.idx[i] = cert_ctx->linked_components.idx[i + 1];
    }
    cert_ctx->linked_components.idx[i] = INVALID_CERT_CTX_IDX;
    cert_ctx->linked_components.count--;
}

static int get_free_component_context_index(void)
{
    int i;

    for (i = 0; i < MAX_NUM_OF_COMPONENTS; i++) {
        if (!component_ctx_array[i].in_use) {
            break;
        }
    }

    if (i >= MAX_NUM_OF_COMPONENTS) {
        /* No free index left in the array -- all used up! */
        return -1;
    }

    return i;
}

static dpe_error_t renew_nonce(int *handle)
{
    uint16_t nonce;

    psa_status_t status = psa_generate_random((uint8_t *)&nonce, sizeof(nonce));
    if (status != PSA_SUCCESS) {
        return DPE_INTERNAL_ERROR;
    }
    *handle = SET_NONCE(*handle, nonce);

    return DPE_NO_ERROR;
}

static void set_context_to_default(int i)
{
    component_ctx_array[i].in_use = false;
    component_ctx_array[i].is_allowed_to_derive = true;
    /* export CDI attribute is inherited and once disabled, a derived context
     * and subsequent derivations cannot export CDI, hence enable by default
     */
    component_ctx_array[i].is_export_cdi_allowed = true;
    component_ctx_array[i].nonce = INVALID_NONCE_VALUE;
    component_ctx_array[i].parent_idx = INVALID_COMPONENT_IDX;
    component_ctx_array[i].linked_cert_ctx_idx = INVALID_CERT_CTX_IDX;
    (void)memset(&component_ctx_array[i].data, 0, sizeof(struct component_context_data_t));
    component_ctx_array[i].target_locality = DEFAULT_TARGET_LOCALITY;
    /* Allow component to be derived by default */
}

static void initialise_certificate_context(int i)
{
    int j;

    cert_ctx_array[i].idx = i;
    cert_ctx_array[i].state = CERT_CTX_UNASSIGNED;
    cert_ctx_array[i].parent_cert_ctx_idx = INVALID_CERT_CTX_IDX;
    cert_ctx_array[i].is_cdi_to_be_exported = false;
    cert_ctx_array[i].is_rot_cert_ctx = false;
    cert_ctx_array[i].cert_id = DPE_CERT_ID_INVALID;
    (void)memset(&cert_ctx_array[i].attest_cdi_hash_input, 0,
                 sizeof(cert_ctx_array[i].attest_cdi_hash_input));
    (void)memset(&cert_ctx_array[i].data, 0, sizeof(struct cert_context_data_t));
    cert_ctx_array[i].data.cdi_key_id = PSA_KEY_ID_NULL;
    cert_ctx_array[i].data.attest_key_id = PSA_KEY_ID_NULL;
    cert_ctx_array[i].linked_components.count = 0;
    for (j = 0; j < ARRAY_SIZE(cert_ctx_array[i].linked_components.idx); j++) {
        cert_ctx_array[i].linked_components.idx[j] = INVALID_COMPONENT_IDX;
    }
}

static void free_certificate_context(int i)
{
    destroy_certificate_context_keys(&cert_ctx_array[i]);
    initialise_certificate_context(i);
}

static dpe_error_t copy_dice_input(struct component_context_t *dest_ctx,
                                   const DiceInputValues *dice_inputs)
{
    size_t hash_len;
    psa_status_t status;

    memcpy(&dest_ctx->data.measurement_value, dice_inputs->code_hash,
           DICE_HASH_SIZE);
    memcpy(&dest_ctx->data.measurement_descriptor,
           dice_inputs->code_descriptor,
           dice_inputs->code_descriptor_size);

    dest_ctx->data.measurement_descriptor_size =
                                      dice_inputs->code_descriptor_size;

    memcpy(&dest_ctx->data.signer_id, dice_inputs->authority_hash, DICE_HASH_SIZE);
    memcpy(&dest_ctx->data.signer_id_descriptor,
           dice_inputs->authority_descriptor,
           dice_inputs->authority_descriptor_size);

    dest_ctx->data.signer_id_descriptor_size =
                                         dice_inputs->authority_descriptor_size;

    if (dice_inputs->config_type == kDiceConfigTypeInline) {
        /* Copy config_value */
        memcpy(&dest_ctx->data.config_value, dice_inputs->config_value,
               DICE_INLINE_CONFIG_SIZE);

    } else {
        /* Copy config descriptor */
        memcpy(&dest_ctx->data.config_descriptor, dice_inputs->config_descriptor,
                dice_inputs->config_descriptor_size);
        dest_ctx->data.config_descriptor_size = dice_inputs->config_descriptor_size;

        /* Calculate config value as hash of input config descriptor */
        status = psa_hash_compute(DPE_HASH_ALG,
                                  dice_inputs->config_descriptor,
                                  dice_inputs->config_descriptor_size,
                                  dest_ctx->data.config_value,
                                  sizeof(dest_ctx->data.config_value),
                                  &hash_len);

        if (status != PSA_SUCCESS) {
            return DPE_INTERNAL_ERROR;
        }
    }

    dest_ctx->data.mode = dice_inputs->mode;
    memcpy(&dest_ctx->data.hidden, dice_inputs->hidden, DICE_HIDDEN_SIZE);

    return DPE_NO_ERROR;
}

static bool is_dice_input_valid(const DiceInputValues *dice_inputs)
{
    if ((dice_inputs->code_descriptor_size > DICE_CODE_DESCRIPTOR_MAX_SIZE) ||
        (dice_inputs->authority_descriptor_size > DICE_AUTHORITY_DESCRIPTOR_MAX_SIZE) ||
        (dice_inputs->config_descriptor_size > DICE_CONFIG_DESCRIPTOR_MAX_SIZE)) {
        return false;
    }

    return true;
}

static bool is_input_handle_valid(int input_context_handle)
{
    uint16_t idx = GET_IDX(input_context_handle);
    uint16_t nonce = GET_NONCE(input_context_handle);

    /* Validate input handle id and nonce */
    if ((idx >= MAX_NUM_OF_COMPONENTS) || (nonce == INVALID_NONCE_VALUE)) {
        return false;
    }

    if (nonce == component_ctx_array[idx].nonce) {
        return true;
    }

    return false;
}

/* Attest_CDI Input requires {measurement_value, config, authority, mode, hidden} in
 * same order
 */
static psa_status_t get_component_data_for_attest_cdi(uint8_t *dest_buf,
                                                      size_t max_size,
                                                      size_t *dest_size,
                                                      const struct component_context_t *comp_ctx)
{
    size_t out_size = 0;

    if ((DICE_HASH_SIZE + DICE_INLINE_CONFIG_SIZE + DICE_HASH_SIZE +
         sizeof(comp_ctx->data.mode) + DICE_HIDDEN_SIZE > max_size )) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(&dest_buf[out_size], comp_ctx->data.measurement_value, DICE_HASH_SIZE);
    out_size += DICE_HASH_SIZE;

    memcpy(&dest_buf[out_size], comp_ctx->data.config_value, DICE_INLINE_CONFIG_SIZE);
    out_size += DICE_INLINE_CONFIG_SIZE;

    memcpy(&dest_buf[out_size], comp_ctx->data.signer_id, DICE_HASH_SIZE);
    out_size += DICE_HASH_SIZE;

    memcpy(&dest_buf[out_size], &comp_ctx->data.mode, sizeof(comp_ctx->data.mode));
    out_size += sizeof(comp_ctx->data.mode);

    memcpy(&dest_buf[out_size], comp_ctx->data.hidden, DICE_HIDDEN_SIZE);
    out_size += DICE_HIDDEN_SIZE;

    *dest_size = out_size;

    return PSA_SUCCESS;
}

static psa_status_t compute_attestation_cdi_input(struct cert_context_t *cert_ctx)
{
    psa_status_t status;
    uint8_t component_ctx_data[CONTEXT_DATA_MAX_SIZE];
    size_t ctx_data_size, hash_len;
    int i, idx;
    uint16_t num_of_linked_components;

    num_of_linked_components = cert_ctx->linked_components.count;
    if (num_of_linked_components == 0) {
        /* No components to hash */
        return PSA_SUCCESS;
    }

    psa_hash_operation_t hash_op = psa_hash_operation_init();
    status = psa_hash_setup(&hash_op, DPE_HASH_ALG);
    if (status != PSA_SUCCESS) {
        return status;
    }

    //TODO:
    /* How to combine measurements of multiple SW components into a single hash
     * is not yet defined by the Open DICE profile. This implementation
     * concatenates the data of all SW components which belong to the same
     * certificate and hash it.
     */
    for (i = 0; i < num_of_linked_components; i++) {
        idx = cert_ctx->linked_components.idx[i];
        status = get_component_data_for_attest_cdi(component_ctx_data,
                                                   sizeof(component_ctx_data),
                                                   &ctx_data_size,
                                                   &component_ctx_array[idx]);
        if (status != PSA_SUCCESS) {
            return status;
        }

        status = psa_hash_update(&hash_op,
                                 component_ctx_data,
                                 ctx_data_size);
        if (status != PSA_SUCCESS) {
            return status;
        }
    }

    status = psa_hash_finish(&hash_op,
                             &cert_ctx->attest_cdi_hash_input[0],
                             sizeof(cert_ctx->attest_cdi_hash_input),
                             &hash_len);

    assert(hash_len == DPE_HASH_ALG_SIZE);

    return status;
}

static dpe_error_t get_encoded_cdi_to_export(struct cert_context_t *cert_ctx,
                                             uint8_t *exported_cdi_buf,
                                             size_t exported_cdi_buf_size,
                                             size_t *exported_cdi_actual_size)
{
    uint8_t cdi_attest_buf[DICE_CDI_SIZE];
    uint8_t cdi_seal_buf[DICE_CDI_SIZE];
    psa_status_t status;
    dpe_error_t err;

    /* Get CDIs value */
    status = get_certificate_cdi_value(cert_ctx,
                                       cdi_attest_buf,
                                       cdi_seal_buf);
    if (status != PSA_SUCCESS) {
        return DPE_INTERNAL_ERROR;
    }

    /* Encode CDI value */
    err = encode_cdi(cdi_attest_buf,
                     cdi_seal_buf,
                     exported_cdi_buf,
                     exported_cdi_buf_size,
                     exported_cdi_actual_size);
    if (err != DPE_NO_ERROR) {
        return err;
    }
    cert_ctx->is_cdi_to_be_exported = true;

    return DPE_NO_ERROR;
}

static dpe_error_t prepare_certificate(struct cert_context_t *cert_ctx,
                                       const struct cert_context_t *parent_cert_ctx)
{
    psa_status_t status;

    /* For RoT certificate, CDI and issuer seed values are calculated by BL1_1 */
    if ((!cert_ctx->is_rot_cert_ctx) &&
        (!cert_ctx->is_external_pub_key_provided)) {

        /* Except for RoT certificate with no external public key supplied */

        status = compute_attestation_cdi_input(cert_ctx);
        if (status != PSA_SUCCESS) {
            return DPE_INTERNAL_ERROR;
        }

        status = derive_attestation_cdi(cert_ctx, parent_cert_ctx);
        if (status != PSA_SUCCESS) {
            return DPE_INTERNAL_ERROR;
        }

        status = derive_sealing_cdi(cert_ctx);
        if (status != PSA_SUCCESS) {
            return DPE_INTERNAL_ERROR;
        }
    }

    status = derive_wrapping_key(cert_ctx);
    if (status != PSA_SUCCESS) {
        return DPE_INTERNAL_ERROR;
    }

    if (!cert_ctx->is_external_pub_key_provided) {
        status = derive_attestation_key(cert_ctx);
        if (status != PSA_SUCCESS) {
            return DPE_INTERNAL_ERROR;
        }
    }

    status = derive_id_from_public_key(cert_ctx);
    if (status != PSA_SUCCESS) {
        return DPE_INTERNAL_ERROR;
    }

    return DPE_NO_ERROR;
}

static uint16_t assign_new_certificate_context(void)
{
    int i;

    for (i = 0; i < MAX_NUM_OF_CERTIFICATES; i++) {
        if (cert_ctx_array[i].state == CERT_CTX_UNASSIGNED) {
            cert_ctx_array[i].state = CERT_CTX_ASSIGNED;
            return i;
        }
    }

    return MAX_NUM_OF_CERTIFICATES - 1;
}

static bool is_client_authorised(int32_t client_id, int32_t target_locality)
{
    int32_t client_locality;

    if (target_locality == LOCALITY_NONE) {
        /* Context is not bound to any locality */
        return true;
    }
    /* Get the corresponding client locality */
    client_locality = dpe_plat_get_client_locality(client_id);

    return (client_locality == target_locality);
}

static bool is_cert_id_used(uint32_t cert_id, uint16_t *cert_ctx_idx)
{
    int i;

    for (i = 0; i < MAX_NUM_OF_CERTIFICATES; i++) {
        if (cert_ctx_array[i].cert_id == cert_id) {
            *cert_ctx_idx = i;
            return true;
        }
    }

    /* No certificate ID match found */
    return false;
}

static dpe_error_t assign_certificate_to_component(struct component_context_t *new_ctx,
                                                   uint32_t cert_id)
{
    uint16_t parent_cert_ctx_idx, cert_ctx_idx_to_link;

    assert(new_ctx->parent_idx < MAX_NUM_OF_COMPONENTS);

    parent_cert_ctx_idx = component_ctx_array[new_ctx->parent_idx].linked_cert_ctx_idx;
    assert(parent_cert_ctx_idx < MAX_NUM_OF_CERTIFICATES);

    if (cert_id != DPE_CERT_ID_INVALID) {
        /* Cert_id was sent by the client */
        if (cert_id == DPE_CERT_ID_SAME_AS_PARENT) {
            if (cert_ctx_array[parent_cert_ctx_idx].state == CERT_CTX_FINALISED) {
                /* Cannot add to the certificate context which is already finalised */
                return DPE_INTERNAL_ERROR;
            }
            /* Derived context belongs to the same certificate as its parent component */
            new_ctx->linked_cert_ctx_idx = parent_cert_ctx_idx;

        } else if (is_cert_id_used(cert_id, &cert_ctx_idx_to_link)) {
            /* Cert_id is already in use but certificate context must be assigned, because
             * cert_id is invalidated when certificate context gets finalized.
             */
            assert(cert_ctx_array[cert_ctx_idx_to_link].state != CERT_CTX_FINALISED);

            /* Use the same certificate context that is associated with cert_id */
            new_ctx->linked_cert_ctx_idx = cert_ctx_idx_to_link;
            /* Linked certificate context's parent is already assigned */

        } else {
            /* Assign new certificate context and link derived context to it */
            cert_ctx_idx_to_link = assign_new_certificate_context();
            if (cert_ctx_idx_to_link == INVALID_CERT_CTX_IDX) {
                return DPE_INTERNAL_ERROR;
            }
            /* Link this context to the new certificate context */
            new_ctx->linked_cert_ctx_idx = cert_ctx_idx_to_link;
            /* New certificate context's parent is parent component's certificate context */
            cert_ctx_array[cert_ctx_idx_to_link].parent_cert_ctx_idx = parent_cert_ctx_idx;
            cert_ctx_array[cert_ctx_idx_to_link].cert_id = cert_id;
        }

    } else {
        /* cert id was not sent by the client */
        //TODO: To be implemented; return error for now.
        return DPE_INVALID_ARGUMENT;
    }

    return DPE_NO_ERROR;
}

/**
 * \brief Create a root of trust component context.
 *
 * \param[out] rot_ctx_handle  A new context handle for the RoT context.
 *
 * \return Returns error code of type dpe_error_t
 */
static dpe_error_t create_rot_context(int *rot_ctx_handle)
{
    struct component_context_t *rot_comp_ctx = &component_ctx_array[0];
    struct cert_context_t *rot_cert_ctx = &cert_ctx_array[DPE_ROT_CERT_CTX_IDX];

    rot_cert_ctx->is_rot_cert_ctx = true;
    /* For RoT certificate, parent and derived context share same index */
    rot_cert_ctx->parent_cert_ctx_idx = DPE_ROT_CERT_CTX_IDX;
    /* Get the RoT CDI key for the RoT certificate */
    rot_cert_ctx->data.cdi_key_id = dpe_plat_get_rot_cdi_key_id();
    /* Init RoT context, ready to be derived in next call to DeriveContext */
    rot_comp_ctx->nonce = 0;
    /* Set the target locality for RoT context */
    rot_comp_ctx->target_locality = LOCALITY_RSE_S;
    /* Parent component index for derived RoT context is same */
    rot_comp_ctx->parent_idx = 0;
    /* Link context to RoT certificate */
    rot_comp_ctx->linked_cert_ctx_idx = DPE_ROT_CERT_CTX_IDX;
    rot_comp_ctx->expected_mhu_id = 0;
    *rot_ctx_handle = 0; /* index = 0, nonce = 0 */

    return DPE_NO_ERROR;
}

dpe_error_t initialise_context_mngr(int *rot_ctx_handle)
{
    int i;

    for (i = 0; i < MAX_NUM_OF_COMPONENTS; i++) {
        set_context_to_default(i);
    }

    for (i = 0; i < MAX_NUM_OF_CERTIFICATES; i++) {
        initialise_certificate_context(i);
    }

    return create_rot_context(rot_ctx_handle);
}

static void free_certificate_context_if_empty(uint16_t cert_ctx_idx)
{
    if (cert_ctx_array[cert_ctx_idx].linked_components.count == 0) {
        free_certificate_context(cert_ctx_idx);
    }
}

dpe_error_t derive_context_request(int input_ctx_handle,
                                   uint32_t cert_id,
                                   bool retain_parent_context,
                                   bool allow_new_context_to_derive,
                                   bool create_certificate,
                                   const DiceInputValues *dice_inputs,
                                   int32_t client_id,
                                   int32_t target_locality,
                                   bool return_certificate,
                                   bool allow_new_context_to_export,
                                   bool export_cdi,
                                   int *new_context_handle,
                                   int *new_parent_context_handle,
                                   uint8_t *new_certificate_buf,
                                   size_t new_certificate_buf_size,
                                   size_t *new_certificate_actual_size,
                                   uint8_t *exported_cdi_buf,
                                   size_t exported_cdi_buf_size,
                                   size_t *exported_cdi_actual_size)
{
    dpe_error_t err;
    struct component_context_t *parent_ctx, *derived_ctx;
    uint16_t parent_ctx_idx, linked_cert_ctx_idx, parent_cert_ctx_idx;
    int free_component_idx;
    struct cert_context_t *cert_ctx, *parent_cert_ctx;

    log_derive_context(input_ctx_handle, cert_id, retain_parent_context,
                       allow_new_context_to_derive, create_certificate, dice_inputs,
                       client_id);

    if (export_cdi && !create_certificate) {
        return DPE_INVALID_ARGUMENT;
    }

    /* Validate dice inputs */
    if (!is_dice_input_valid(dice_inputs)) {
        return DPE_INVALID_ARGUMENT;
    }

    /* Validate input handle */
    if (!is_input_handle_valid(input_ctx_handle)) {
        return DPE_INVALID_ARGUMENT;
    }
    /* Get parent component index from the input handle */
    parent_ctx_idx = GET_IDX(input_ctx_handle);

    /* Below check is for safety only; It should not happen
     * parent_ctx_idx is already checked above in is_input_handle_valid()
     */
    assert(parent_ctx_idx < MAX_NUM_OF_COMPONENTS);

    parent_ctx = &component_ctx_array[parent_ctx_idx];

    /* Check if parent context is allowed to derive */
    if (!parent_ctx->is_allowed_to_derive) {
        return DPE_INVALID_ARGUMENT;
    }

    if (!is_client_authorised(client_id, parent_ctx->target_locality)) {
        return DPE_INVALID_ARGUMENT;
    }

    /* Get next free component index to add new derived context */
    free_component_idx = get_free_component_context_index();
    if (free_component_idx < 0) {
        return DPE_INSUFFICIENT_MEMORY;
    }

    derived_ctx = &component_ctx_array[free_component_idx];
    if (parent_ctx->is_export_cdi_allowed && allow_new_context_to_export) {
        /* If parent context has export enabled and input allow_new_context_to_export
         * is true, then allow context CDI to be exported for derived context
         */
        derived_ctx->is_export_cdi_allowed = true;
    } else {
        /* Export of new context CDI is NOT allowed */
        derived_ctx->is_export_cdi_allowed = false;
        if (export_cdi) {
            return DPE_INVALID_ARGUMENT;
        }
    }

    /* Copy dice input to the new derived component context */
    err = copy_dice_input(derived_ctx, dice_inputs);
    if (err != DPE_NO_ERROR) {
        return err;
    }
    derived_ctx->target_locality = target_locality;

    /* Update parent idx in new derived component context */
    derived_ctx->parent_idx = parent_ctx_idx;
    /* Mark new derived component index as in use */
    derived_ctx->in_use = true;
    derived_ctx->is_allowed_to_derive = allow_new_context_to_derive;
    /* Assign certificate to the component */
    err = assign_certificate_to_component(derived_ctx, cert_id);
    if (err != DPE_NO_ERROR) {
        return err;
    }

    linked_cert_ctx_idx = derived_ctx->linked_cert_ctx_idx;
    assert(linked_cert_ctx_idx < MAX_NUM_OF_CERTIFICATES);
    cert_ctx = &cert_ctx_array[linked_cert_ctx_idx];
    err = store_linked_component(cert_ctx, free_component_idx);
    if (err != DPE_NO_ERROR) {
        goto clean_up_and_exit;
    }
    parent_cert_ctx_idx = cert_ctx->parent_cert_ctx_idx;
    assert(parent_cert_ctx_idx < MAX_NUM_OF_CERTIFICATES);
    parent_cert_ctx = &cert_ctx_array[parent_cert_ctx_idx];

    if (create_certificate) {
        cert_ctx->is_cdi_to_be_exported = export_cdi;

        /* Finalise the certificate context */
        cert_ctx->state = CERT_CTX_FINALISED;
        cert_ctx->cert_id = DPE_CERT_ID_INVALID; /* make same cert_id reusable */
        err = prepare_certificate(cert_ctx, parent_cert_ctx);
        if (err != DPE_NO_ERROR) {
            goto clean_up_and_exit;
        }

        if (return_certificate) {
            /* Encode and return generated certificate */
            err = encode_certificate(cert_ctx,
                                     new_certificate_buf,
                                     new_certificate_buf_size,
                                     new_certificate_actual_size);
            if (err != DPE_NO_ERROR) {
                goto clean_up_and_exit;
            }
        }
    }

    if (export_cdi) {
        err = get_encoded_cdi_to_export(cert_ctx,
                                        exported_cdi_buf,
                                        exported_cdi_buf_size,
                                        exported_cdi_actual_size);
        if (err != DPE_NO_ERROR) {
            goto clean_up_and_exit;
        }
    }

    if (retain_parent_context) {
        /* Retain and return parent handle with renewed nonce */
        *new_parent_context_handle = input_ctx_handle;
        err = renew_nonce(new_parent_context_handle);
        if (err != DPE_NO_ERROR) {
            goto clean_up_and_exit;
        }
        parent_ctx->nonce = GET_NONCE(*new_parent_context_handle);

    } else {
        /* Return invalid handle */
        *new_parent_context_handle = INVALID_HANDLE;
        parent_ctx->nonce = INVALID_NONCE_VALUE;
    }

    if (!export_cdi) {
        /* Return handle to derived context */
        *new_context_handle = SET_IDX(*new_context_handle, free_component_idx);
        err = renew_nonce(new_context_handle);
        if (err != DPE_NO_ERROR) {
            return err;
        }
        /* Update nonce in new derived component context */
        derived_ctx->nonce = GET_NONCE(*new_context_handle);

    } else {
        /* Return invalid handle */
        *new_context_handle = INVALID_HANDLE;
        derived_ctx->nonce = INVALID_NONCE_VALUE;
    }

    log_derive_context_output_handles(*new_parent_context_handle,
                                      *new_context_handle);

    /* Log component context, certificate context & certificate if no error */
    log_dpe_component_ctx_metadata(derived_ctx, free_component_idx);
    log_dpe_cert_ctx_metadata(cert_ctx, linked_cert_ctx_idx);
    if (return_certificate) {
        log_intermediate_certificate(linked_cert_ctx_idx,
                                     new_certificate_buf,
                                     *new_certificate_actual_size);
    }

    return DPE_NO_ERROR;

clean_up_and_exit:
    set_context_to_default(free_component_idx);
    free_certificate_context_if_empty(linked_cert_ctx_idx);

    return err;
}

dpe_error_t destroy_context_request(int input_ctx_handle,
                                    bool destroy_recursively)
{
    uint16_t input_ctx_idx, linked_cert_ctx_idx;
    struct cert_context_t *cert_ctx;

    log_destroy_context(input_ctx_handle, destroy_recursively);

    /* Get component index and linked certificate context from the input handle */
    input_ctx_idx = GET_IDX(input_ctx_handle);

    /* Validate input handle */
    if (!is_input_handle_valid(input_ctx_handle)) {
        return DPE_INVALID_ARGUMENT;
    }
    linked_cert_ctx_idx = component_ctx_array[input_ctx_idx].linked_cert_ctx_idx;

#ifndef DPE_TEST_MODE
    if (linked_cert_ctx_idx <= DPE_DESTROY_CONTEXT_THRESHOLD_CERT_CTX_IDX) {
        /* All certificate contexts till hypervisor cannot be destroyed dynamically */
        return DPE_INVALID_ARGUMENT;
    }
#endif /* !DPE_TEST_MODE */

    assert(linked_cert_ctx_idx < MAX_NUM_OF_CERTIFICATES);

    if (!destroy_recursively) {
        set_context_to_default(input_ctx_idx);
        cert_ctx = &cert_ctx_array[linked_cert_ctx_idx];
        remove_linked_component(cert_ctx, input_ctx_idx);
    } else {
        //TODO: To be implemented
    }

    /* Free the certificate context if all of its components are destroyed */
    free_certificate_context_if_empty(linked_cert_ctx_idx);

    return DPE_NO_ERROR;
}

struct component_context_t* get_component_ctx_ptr(uint16_t component_idx)
{
    /* Safety case */
    if (component_idx >= MAX_NUM_OF_COMPONENTS) {
        return NULL;
    }

    return &component_ctx_array[component_idx];
}

struct cert_context_t* get_cert_ctx_ptr(uint16_t cert_ctx_idx)
{
    /* Safety case */
    if (cert_ctx_idx >= MAX_NUM_OF_CERTIFICATES) {
        return NULL;
    }

    return &cert_ctx_array[cert_ctx_idx];
}

dpe_error_t certify_key_request(int input_ctx_handle,
                                bool retain_context,
                                const uint8_t *public_key,
                                size_t public_key_size,
                                const uint8_t *label,
                                size_t label_size,
                                uint8_t *certificate_buf,
                                size_t certificate_buf_size,
                                size_t *certificate_actual_size,
                                uint8_t *derived_public_key_buf,
                                size_t derived_public_key_buf_size,
                                size_t *derived_public_key_actual_size,
                                int *new_context_handle)
{
    uint16_t input_ctx_idx, input_cert_ctx_idx, parent_cert_ctx_idx;
    dpe_error_t err;
    psa_status_t status;
    struct cert_context_t *parent_cert_ctx, *input_cert_ctx;
    struct cert_context_t leaf_cert_ctx = {0};

    log_certify_key(input_ctx_handle, retain_context, public_key, public_key_size,
                    label, label_size);

    /* Validate input handle */
    if (!is_input_handle_valid(input_ctx_handle)) {
        return DPE_INVALID_ARGUMENT;
    }

    if (label_size > DPE_EXTERNAL_LABEL_MAX_SIZE) {
        return DPE_INVALID_ARGUMENT;
    }

    /* Get component index from the input handle */
    input_ctx_idx = GET_IDX(input_ctx_handle);
    /* Get current linked certificate context idx */
    input_cert_ctx_idx = component_ctx_array[input_ctx_idx].linked_cert_ctx_idx;
    assert(input_cert_ctx_idx < MAX_NUM_OF_CERTIFICATES);
    input_cert_ctx = &cert_ctx_array[input_cert_ctx_idx];

    if (input_cert_ctx->state == CERT_CTX_FINALISED) {
        /* Input certificate context is finalised,
         * new leaf certificate context is its child now
         */
        leaf_cert_ctx.parent_cert_ctx_idx = input_cert_ctx_idx;
        /* Linked components count already initialised to 0 */

    } else {
        /* Input certificate context is not finalised,
         * new leaf certificate context share the same components as in the
         * input certificate context
         */
        memcpy(&leaf_cert_ctx.linked_components, &input_cert_ctx->linked_components,
                sizeof(input_cert_ctx->linked_components));
    }

    if (public_key_size > sizeof(leaf_cert_ctx.data.attest_pub_key)) {
        return DPE_INVALID_ARGUMENT;
    }

    if ((public_key_size > 0) && (public_key != NULL)) {
        leaf_cert_ctx.is_external_pub_key_provided = true;
        /* Copy the public key provided */
        memcpy(&leaf_cert_ctx.data.attest_pub_key[0],
               public_key,
               public_key_size);
        leaf_cert_ctx.data.attest_pub_key_len = public_key_size;

        /* If public key is provided, then provided label (if any) is ignored */
        leaf_cert_ctx.data.external_key_deriv_label_len = 0;

    } else {
        /* No external public key is provided */
        leaf_cert_ctx.is_external_pub_key_provided = false;

        if ((label_size > 0) && (label != NULL)) {
            /* Copy the label provided */
            memcpy(&leaf_cert_ctx.data.external_key_deriv_label[0],
                   label,
                   label_size);
            leaf_cert_ctx.data.external_key_deriv_label_len = label_size;

        } else {
            leaf_cert_ctx.data.external_key_deriv_label_len = 0;
        }
    }

    /* Get parent certificate's derived public key to verify the certificate signature */
    parent_cert_ctx_idx = leaf_cert_ctx.parent_cert_ctx_idx;
    assert(parent_cert_ctx_idx < MAX_NUM_OF_CERTIFICATES);
    parent_cert_ctx = &cert_ctx_array[parent_cert_ctx_idx];

    /* Correct certificate context should already be assigned in last call of
     * derive context command
     */
    /* Create leaf certificate */
    err = prepare_certificate(&leaf_cert_ctx, parent_cert_ctx);
    if (err != DPE_NO_ERROR) {
        return err;
    }

    err = encode_certificate(&leaf_cert_ctx,
                                   certificate_buf,
                                   certificate_buf_size,
                                   certificate_actual_size);
    if (err != DPE_NO_ERROR) {
        return err;
    }

    if (derived_public_key_buf_size < sizeof(parent_cert_ctx->data.attest_pub_key)) {
        return DPE_INVALID_ARGUMENT;
    }

    memcpy(derived_public_key_buf,
           &parent_cert_ctx->data.attest_pub_key[0],
           parent_cert_ctx->data.attest_pub_key_len);
    *derived_public_key_actual_size = parent_cert_ctx->data.attest_pub_key_len;

    /* Renew handle for the same context, if requested */
    if (retain_context) {
        *new_context_handle = input_ctx_handle;
        status = renew_nonce(new_context_handle);
        if (status != PSA_SUCCESS) {
            return DPE_INTERNAL_ERROR;
        }
        component_ctx_array[input_ctx_idx].nonce = GET_NONCE(*new_context_handle);

    } else {
        *new_context_handle = INVALID_HANDLE;
        component_ctx_array[input_ctx_idx].nonce = INVALID_NONCE_VALUE;
    }

    log_certify_key_output_handle(*new_context_handle);
    log_intermediate_certificate(input_cert_ctx_idx,
                                 certificate_buf,
                                 *certificate_actual_size);

    destroy_certificate_context_keys(&leaf_cert_ctx);

    return DPE_NO_ERROR;
}

dpe_error_t get_certificate_chain_request(int input_ctx_handle,
                                          bool retain_context,
                                          bool clear_from_context,
                                          uint8_t *certificate_chain_buf,
                                          size_t certificate_chain_buf_size,
                                          size_t *certificate_chain_actual_size,
                                          int *new_context_handle)
{
    dpe_error_t err;
    uint16_t input_ctx_idx, input_cert_ctx_idx;
    psa_status_t status;
    struct cert_context_t *cert_ctx;

    log_get_certificate_chain(input_ctx_handle, retain_context,
                              clear_from_context, certificate_chain_buf_size);

    /* Validate input handle */
    if (!is_input_handle_valid(input_ctx_handle)) {
        return DPE_INVALID_ARGUMENT;
    }

    /* Get component index from the input handle */
    input_ctx_idx = GET_IDX(input_ctx_handle);
    /* Get current linked certificate context idx */
    input_cert_ctx_idx = component_ctx_array[input_ctx_idx].linked_cert_ctx_idx;
    assert(input_cert_ctx_idx < MAX_NUM_OF_CERTIFICATES);

    cert_ctx = &cert_ctx_array[input_cert_ctx_idx];
    if (cert_ctx->state != CERT_CTX_FINALISED) {
        /* If the context has accumulated info and not yet part of a certificate,
         * return an invalid-argument error
         */
        return DPE_INVALID_ARGUMENT;
    }

    err = get_certificate_chain(cert_ctx,
                                certificate_chain_buf,
                                certificate_chain_buf_size,
                                certificate_chain_actual_size);
    if (err != DPE_NO_ERROR) {
        return err;
    }

    log_certificate_chain(certificate_chain_buf, *certificate_chain_actual_size);

    /* Renew handle for the same context, if requested */
    if (retain_context) {
        *new_context_handle = input_ctx_handle;
        status = renew_nonce(new_context_handle);
        if (status != PSA_SUCCESS) {
            return DPE_INTERNAL_ERROR;
        }
        component_ctx_array[input_ctx_idx].nonce = GET_NONCE(*new_context_handle);

        if (clear_from_context) {
        //TODO: Reimplement the clear_from_context functionality after memory
        //      optimization; Certificates are not ready made and they are not
        //      stored in the certificate context anymore. They are created on-the-fly
        //      when requested. Add a test as well.
        }

    } else {
        *new_context_handle = INVALID_HANDLE;
        component_ctx_array[input_ctx_idx].nonce = INVALID_NONCE_VALUE;
    }
    log_get_certificate_chain_output_handle(*new_context_handle);

    return DPE_NO_ERROR;
}
