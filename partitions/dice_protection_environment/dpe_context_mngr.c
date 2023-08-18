/*
 * Copyright (c) 2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "dpe_context_mngr.h"
#include <assert.h>
#include <string.h>
#include "dice_protection_environment.h"
#include "dpe_certificate.h"
#include "dpe_crypto_interface.h"
#include "dpe_log.h"
#include "psa/crypto.h"

#ifdef TFM_S_REG_TEST
#define TEST_ROT_CDI_VAL {                                                  \
                            0xD2, 0x90, 0x66, 0x07, 0x2A, 0x2D, 0x2A, 0x00, \
                            0x91, 0x9D, 0xD9, 0x15, 0x14, 0xBE, 0x2D, 0xCC, \
                            0xA3, 0x9F, 0xDE, 0xC3, 0x35, 0x75, 0x84, 0x6E, \
                            0x4C, 0xB9, 0x28, 0xAC, 0x7A, 0x4E, 0X00, 0x7F  \
                         }

#define TEST_ROT_ISSUER_SEED {                                                  \
                                0xD2, 0x90, 0x66, 0x07, 0x2A, 0x2D, 0x2A, 0x00, \
                                0x91, 0x9D, 0xD9, 0x15, 0x14, 0xBE, 0x2D, 0xCC, \
                                0xA3, 0x9F, 0xDE, 0xC3, 0x35, 0x75, 0x84, 0x6E, \
                                0x4C, 0xB9, 0x28, 0xAC, 0x7A, 0x4E, 0X00, 0x7F  \
                             }

#endif /* TFM_S_REG_TEST */

#define CONTEXT_DATA_MAX_SIZE sizeof(struct component_context_data_t)

static struct component_context_t component_ctx_array[MAX_NUM_OF_COMPONENTS];
static struct layer_context_t layer_ctx_array[MAX_NUM_OF_LAYERS];

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

static inline void invalidate_handle(int *handle)
{
    *handle = INVALID_HANDLE;
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

static dpe_error_t generate_new_handle(int *out_handle)
{
    /* Find the free component array element */
    int free_component_idx = get_free_component_context_index();
    if (free_component_idx < 0) {
        return DPE_INSUFFICIENT_MEMORY;
    }

    *out_handle = SET_IDX(*out_handle, free_component_idx);

    return renew_nonce(out_handle);
}

static void set_context_to_default(int i)
{
    component_ctx_array[i].in_use = false;
    component_ctx_array[i].is_leaf = false;
    component_ctx_array[i].nonce = INVALID_NONCE_VALUE;
    component_ctx_array[i].parent_idx = INVALID_COMPONENT_IDX;
    component_ctx_array[i].linked_layer_idx = INVALID_LAYER_IDX;
    (void)memset(&component_ctx_array[i].data, 0, sizeof(struct component_context_data_t));
    //TODO: Question: how to initialise MHU Id mapping?
    /* Allow component to be derived by default */
}

static void invalidate_layer(int i)
{
    layer_ctx_array[i].state = LAYER_STATE_CLOSED;
    layer_ctx_array[i].parent_layer_idx = INVALID_LAYER_IDX;
    (void)memset(&layer_ctx_array[i].attest_cdi_hash_input, 0,
                 sizeof(layer_ctx_array[i].attest_cdi_hash_input));
    (void)psa_destroy_key(layer_ctx_array[i].data.cdi_key_id);
    (void)psa_destroy_key(layer_ctx_array[i].data.attest_key_id);
    (void)memset(&layer_ctx_array[i].data, 0, sizeof(struct layer_context_data_t));
}

void initialise_all_dpe_contexts(void)
{
    int i;

    for (i = 0; i < MAX_NUM_OF_COMPONENTS; i++) {
        set_context_to_default(i);
    }

    for (i = 0; i < MAX_NUM_OF_LAYERS; i++) {
        invalidate_layer(i);
    }
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

static psa_status_t compute_layer_cdi_attest_input(uint16_t curr_layer_idx)
{
    psa_status_t status;
    uint8_t component_ctx_data[CONTEXT_DATA_MAX_SIZE];
    size_t ctx_data_size, hash_len;
    int idx;

    psa_hash_operation_t hash_op = psa_hash_operation_init();
    status = psa_hash_setup(&hash_op, DPE_HASH_ALG);
    if (status != PSA_SUCCESS) {
        return status;
    }

    //TODO:
    /* How to combine measurements of multiple SW components into a single hash
     * is not yet defined by the Open DICE profile. This implementation
     * concatenates the data of all SW components which belong to the same layer
     * and hash it.
     */
    for (idx = 0; idx < MAX_NUM_OF_COMPONENTS; idx++) {
        if (component_ctx_array[idx].linked_layer_idx == curr_layer_idx) {
            /* This component belongs to current layer */
            /* Concatenate all context data for this component */
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
    }

    if (layer_ctx_array[curr_layer_idx].data.attest_key_label_len != 0) {

        status = psa_hash_update(&hash_op,
                                 &layer_ctx_array[curr_layer_idx].data.attest_key_label[0],
                                 layer_ctx_array[curr_layer_idx].data.attest_key_label_len);
        if (status != PSA_SUCCESS) {
            return status;
        }
    }

    status = psa_hash_finish(&hash_op,
                             &layer_ctx_array[curr_layer_idx].attest_cdi_hash_input[0],
                             sizeof(layer_ctx_array[curr_layer_idx].attest_cdi_hash_input),
                             &hash_len);

    assert(hash_len == DPE_HASH_ALG_SIZE);

    return status;
}

static dpe_error_t create_layer_certificate(uint16_t layer_idx)
{
    uint16_t parent_layer_idx;
    psa_status_t status;
    dpe_error_t err;
    struct layer_context_t *layer_ctx, *parent_layer_ctx;

    assert(layer_idx < MAX_NUM_OF_LAYERS);
    layer_ctx = &layer_ctx_array[layer_idx];
   /* Finalise the layer */
    layer_ctx->state = LAYER_STATE_FINALISED;
    parent_layer_idx = layer_ctx->parent_layer_idx;
    assert(parent_layer_idx < MAX_NUM_OF_LAYERS);
    parent_layer_ctx = &layer_ctx_array[parent_layer_idx];

    /* For RoT Layer, CDI and issuer seed values are calculated by BL1_1 */
    if ((layer_idx != DPE_ROT_LAYER_IDX) &&
        (!layer_ctx->is_external_pub_key_provided)) {

        /* Except for RoT Layer with no external public key supplied */

        status = compute_layer_cdi_attest_input(layer_idx);
        if (status != PSA_SUCCESS) {
            return DPE_INTERNAL_ERROR;
        }

        status = derive_attestation_cdi(layer_ctx, parent_layer_ctx);
        if (status != PSA_SUCCESS) {
            return DPE_INTERNAL_ERROR;
        }

        status = derive_sealing_cdi(layer_ctx);
        if (status != PSA_SUCCESS) {
            return DPE_INTERNAL_ERROR;
        }
    }

    status = derive_wrapping_key(layer_ctx);
    if (status != PSA_SUCCESS) {
        return DPE_INTERNAL_ERROR;
    }

    if (!layer_ctx->is_external_pub_key_provided) {
        status = derive_attestation_key(layer_ctx);
        if (status != PSA_SUCCESS) {
            return DPE_INTERNAL_ERROR;
        }
    }

    status = derive_id_from_public_key(layer_ctx);
    if (status != PSA_SUCCESS) {
        return DPE_INTERNAL_ERROR;
    }

    err = encode_layer_certificate(layer_idx,
                                   layer_ctx,
                                   parent_layer_ctx);
    if (err != DPE_NO_ERROR) {
        return err;
    }

    log_intermediate_certificate(layer_idx,
                                 &layer_ctx->data.cert_buf[0],
                                 layer_ctx->data.cert_buf_len);

    return store_layer_certificate(layer_ctx);
}

static uint16_t open_new_layer(void)
{
    int i;

    for (i = 0; i < MAX_NUM_OF_LAYERS; i++) {
        if (layer_ctx_array[i].state == LAYER_STATE_CLOSED) {
            layer_ctx_array[i].state = LAYER_STATE_OPEN;
            return i;
        }
    }

    //TODO: There is an open issue of layer creation as described below.
    /* This is causing extra unintended layers to open. Since each layer
     * has some context data and certificate buffer of 3k, it is
     * causing RAM overflow. Hence until resoluton is reached, once all
     * layers are opened, link new compenents to the last layer.
     * ISSUE DESCRIPTION: We derive AP_BL31 as child of AP BL2 with create_certificate
     * as true. Hence we finalize Platform layer. Then we derive AP_SPM as child of
     * AP BL2, but since AP BL2 is finalised, we open new layer (Hypervisor layer).
     * Then we derive AP SPx as child of AP BL2. Again, since AP BL2 is finalised,
     * we open new layer! Here AP SPx should belong to same layer as AP SPM.
     */
    return MAX_NUM_OF_LAYERS - 1;
}

static inline void link_layer(uint16_t child_layer, uint16_t parent_layer)
{
    layer_ctx_array[child_layer].parent_layer_idx = parent_layer;
}

dpe_error_t derive_rot_context(const DiceInputValues *dice_inputs,
                               int *new_child_ctx_handle,
                               int *new_parent_ctx_handle)
{
    int status;
    struct component_context_t *child_comp_ctx, *new_child_ctx;
    uint16_t new_layer_idx;

    log_derive_rot_context(dice_inputs);

    /* Validate dice inputs */
    if (!is_dice_input_valid(dice_inputs)) {
        return DPE_INVALID_ARGUMENT;
    }

    child_comp_ctx = &component_ctx_array[0];
    status = copy_dice_input(child_comp_ctx, dice_inputs);
    if (status != DPE_NO_ERROR) {
        return status;
    }

    child_comp_ctx->in_use = true;
    /* Link context to RoT Layer */
    child_comp_ctx->linked_layer_idx = DPE_ROT_LAYER_IDX;
    /* There is no parent for RoT layer */
    layer_ctx_array[DPE_ROT_LAYER_IDX].parent_layer_idx = 0;

    /* Parent is same as child for RoT context */
    child_comp_ctx->parent_idx = 0;
    /* Parent not deriving any more children */
    invalidate_handle(new_parent_ctx_handle);

    //TODO: Update expected_mhu_id of derived child
    /* Create certificate for RoT layer */
    status = create_layer_certificate(DPE_ROT_LAYER_IDX);
    if (status != DPE_NO_ERROR) {
        return status;
    }

    /* Generate new handle for child for subsequent requests */
    if (generate_new_handle(new_child_ctx_handle) != DPE_NO_ERROR) {
        return DPE_INTERNAL_ERROR;
    }

    /* Update the component context array element as pointed by newly generated handle */
    new_child_ctx = &component_ctx_array[GET_IDX(*new_child_ctx_handle)];
    new_child_ctx->nonce = GET_NONCE(*new_child_ctx_handle);
    new_child_ctx->in_use = true;
    /* New child's parent is current RoT component which is evaluated as 0 */
    new_child_ctx->parent_idx = 0;

    /* Open new layer since RoT layer is finalised and
     * link the new child to this new layer
     */
    new_layer_idx = open_new_layer();
    new_child_ctx->linked_layer_idx = new_layer_idx;

    /* Link this new layer to the RoT Layer */
    link_layer(new_layer_idx, DPE_ROT_LAYER_IDX);

    return DPE_NO_ERROR;
}

static inline bool is_input_client_id_valid(int32_t client_id)
{
    //TODO: Waiting for implementation
    return true;
}

static dpe_error_t assign_layer_to_context(struct component_context_t *new_ctx)
{
    uint16_t new_layer_idx, parent_layer_idx;

    assert(new_ctx->parent_idx < MAX_NUM_OF_COMPONENTS);

    parent_layer_idx = component_ctx_array[new_ctx->parent_idx].linked_layer_idx;
    assert(parent_layer_idx < MAX_NUM_OF_LAYERS);

    if (layer_ctx_array[parent_layer_idx].state == LAYER_STATE_FINALISED) {
        /* Parent comp's layer of new child is finalised; open a new layer */
        new_layer_idx = open_new_layer();
        if (new_layer_idx == INVALID_LAYER_IDX) {
            return DPE_INTERNAL_ERROR;
        }
        /* Link this context to the new layer */
        new_ctx->linked_layer_idx = new_layer_idx;
        /* New layer's parent is current layer */
        link_layer(new_layer_idx, parent_layer_idx);

    } else {
        /* Parent comp's layer is not yet finalised, link
         * new component to the same layer as parent
         */
        new_ctx->linked_layer_idx = parent_layer_idx;
    }

    return DPE_NO_ERROR;
}

dpe_error_t derive_child_request(int input_ctx_handle,
                                 bool retain_parent_context,
                                 bool allow_child_to_derive,
                                 bool create_certificate,
                                 const DiceInputValues *dice_inputs,
                                 int32_t client_id,
                                 int *new_child_ctx_handle,
                                 int *new_parent_ctx_handle)
{
    dpe_error_t err;
    struct component_context_t *child_ctx, *parent_ctx, *new_ctx;
    uint16_t input_child_idx, input_parent_idx;

#ifdef TFM_S_REG_TEST
    //TODO: Remove this TEST_ROT_CDI_VAL CDI once actual CDI is calculated by BL1_1
    psa_status_t status;
    uint8_t dpe_rot_cdi[DICE_CDI_SIZE] = TEST_ROT_CDI_VAL;

    if (layer_ctx_array[DPE_ROT_LAYER_IDX].state != LAYER_STATE_FINALISED) {

        status = create_layer_cdi_key(&layer_ctx_array[DPE_ROT_LAYER_IDX],
                                      &dpe_rot_cdi[0],
                                      sizeof(dpe_rot_cdi));
        if (status != PSA_SUCCESS) {
            return status;
        }

        return derive_rot_context(dice_inputs,
                                  new_child_ctx_handle,
                                  new_parent_ctx_handle);
    }
#endif /* TFM_S_REG_TEST */

    log_derive_child(input_ctx_handle, retain_parent_context,
                     allow_child_to_derive, create_certificate, dice_inputs,
                     client_id);

    /* Validate dice inputs */
    if (!is_dice_input_valid(dice_inputs)) {
        return DPE_INVALID_ARGUMENT;
    }

    /* Validate input handle */
    if (!is_input_handle_valid(input_ctx_handle)) {
        return DPE_INVALID_ARGUMENT;
    }
    /* Get child component index from the input handle */
    input_child_idx = GET_IDX(input_ctx_handle);
    /* Get parent index of input referenced child component */
    input_parent_idx = component_ctx_array[input_child_idx].parent_idx;

    /* Below check is for safety only; It should not happen
     * input_child_idx is already checked above in is_input_handle_valid()
     */
    assert(input_parent_idx < MAX_NUM_OF_COMPONENTS);

    child_ctx = &component_ctx_array[input_child_idx];
    parent_ctx = &component_ctx_array[input_parent_idx];

    //TODO:  Question: how to get mhu id of incoming request?
    if (!is_input_client_id_valid(client_id)) {
        return DPE_INVALID_ARGUMENT;
    }

    /* Copy dice input to the child component context */
    err = copy_dice_input(child_ctx, dice_inputs);
    if (err != DPE_NO_ERROR) {
        return err;
    }

    if (create_certificate) {
        err = create_layer_certificate(child_ctx->linked_layer_idx);
        if (err != DPE_NO_ERROR) {
            return err;
        }
    }

    if (allow_child_to_derive) {
        /* Generate new handle for child for subsequent requests */
        if (generate_new_handle(new_child_ctx_handle) != DPE_NO_ERROR) {
            return DPE_INTERNAL_ERROR;
        }
        /* Update the component context array element as pointed by newly generated handle */
        new_ctx = &component_ctx_array[GET_IDX(*new_child_ctx_handle)];
        /* Update nonce in new child component context */
        new_ctx->nonce = GET_NONCE(*new_child_ctx_handle);
        /* Update parent idx in new child component context */
        new_ctx->parent_idx = input_child_idx;
        /* Mark new child component index as in use */
        new_ctx->in_use = true;
        status = assign_layer_to_context(new_ctx);
        if (status != DPE_NO_ERROR) {
            return status;
        }
    } else {
        /* Child not deriving any children */
        /* Tag this component as a leaf */
        child_ctx->is_leaf = true;
        invalidate_handle(new_child_ctx_handle);
        /* Renew nonce of child context so it cannot be used again */
        child_ctx->nonce = INVALID_NONCE_VALUE;
    }

    if (retain_parent_context) {
        /* Parent deriving multiple children */
        /* Generate new handle for child for the same parent for subsequent requests */
        if (generate_new_handle(new_parent_ctx_handle) != DPE_NO_ERROR) {
            return DPE_INTERNAL_ERROR;
        }
        /* Update the component context array element as pointed by newly generated handle */
        new_ctx = &component_ctx_array[GET_IDX(*new_parent_ctx_handle)];
        /* Update nonce in new child component context */
        new_ctx->nonce = GET_NONCE(*new_parent_ctx_handle);
        /* Update parent idx in new child component context */
        new_ctx->parent_idx = input_parent_idx;
        /* Mark new child component index as in use */
        new_ctx->in_use = true;
        status = assign_layer_to_context(new_ctx);
        if (status != DPE_NO_ERROR) {
            return status;
        }
    } else {
        /* Parent not deriving any more children */
        /* No need to return parent handle */
        invalidate_handle(new_parent_ctx_handle);
        /* Renew nonce of parent context so it cannot be used again */
        parent_ctx->nonce = INVALID_NONCE_VALUE;
    }

    return DPE_NO_ERROR;
}

dpe_error_t destroy_context_request(int input_ctx_handle,
                                    bool destroy_recursively)
{
    uint16_t input_ctx_idx, linked_layer_idx;
    int i;
    bool is_layer_empty;

    log_destroy_context(input_ctx_handle, destroy_recursively);

    /* Get child component index and linked layer from the input handle */
    input_ctx_idx = GET_IDX(input_ctx_handle);

#ifdef TFM_S_REG_TEST
    if (input_ctx_idx == 0) {
        invalidate_layer(DPE_ROT_LAYER_IDX);
        set_context_to_default(0);
        return DPE_NO_ERROR;
    }
#endif /* TFM_S_REG_TEST */

    /* Validate input handle */
    if (!is_input_handle_valid(input_ctx_handle)) {
        return DPE_INVALID_ARGUMENT;
    }
    linked_layer_idx = component_ctx_array[input_ctx_idx].linked_layer_idx;

#ifndef TFM_S_REG_TEST
    if (linked_layer_idx <= DPE_DESTROY_CONTEXT_THRESHOLD_LAYER_IDX) {
        /* All layers till hypervisor cannot be destroyed dynamically */
        return DPE_INVALID_ARGUMENT;
    }
#endif /* !TFM_S_REG_TEST */


    if (!destroy_recursively) {
        set_context_to_default(input_ctx_idx);
    } else {
        //TODO: To be implemented
    }

    assert(linked_layer_idx < MAX_NUM_OF_LAYERS);

    /* Close the layer if all of its contexts are destroyed */
    is_layer_empty = true;
    for (i = 0; i < MAX_NUM_OF_COMPONENTS; i++) {
        if (component_ctx_array[i].linked_layer_idx == linked_layer_idx) {
            /* There are active component context in the layer */
            is_layer_empty = false;
            break;
        }
    }

    if (is_layer_empty) {
        invalidate_layer(linked_layer_idx);
    }

    return DPE_NO_ERROR;
}

struct component_context_t* get_component_if_linked_to_layer(uint16_t layer_idx,
                                                             uint16_t component_idx)
{
    /* Safety case */
    if (component_idx >= MAX_NUM_OF_COMPONENTS) {
        return NULL;
    }

    if (component_ctx_array[component_idx].linked_layer_idx == layer_idx) {
        return &component_ctx_array[component_idx];
    } else {
        return NULL;
    }
}

struct layer_context_t* get_layer_ctx_ptr(uint16_t layer_idx)
{
    /* Safety case */
    if (layer_idx >= MAX_NUM_OF_LAYERS) {
        return NULL;
    }

    return &layer_ctx_array[layer_idx];
}

dpe_error_t certify_key_request(int input_ctx_handle,
                                bool retain_context,
                                const uint8_t *public_key,
                                size_t public_key_size,
                                const uint8_t *label,
                                size_t label_size,
                                uint8_t *certificate_chain_buf,
                                size_t certificate_chain_buf_size,
                                size_t *certificate_chain_actual_size,
                                uint8_t *derived_public_key_buf,
                                size_t derived_public_key_buf_size,
                                size_t *derived_public_key_actual_size,
                                int *new_context_handle)
{
    uint16_t input_ctx_idx, input_layer_idx, parent_layer_idx;
    dpe_error_t err;
    psa_status_t status;
    struct layer_context_t *parent_layer_ctx, *layer_ctx;

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
    /* Get current linked layer idx */
    input_layer_idx = component_ctx_array[input_ctx_idx].linked_layer_idx;
    assert(input_layer_idx < MAX_NUM_OF_LAYERS);

    layer_ctx = &layer_ctx_array[input_layer_idx];
    if (public_key_size > sizeof(layer_ctx->data.attest_pub_key)) {
        return DPE_INVALID_ARGUMENT;
    }

    if ((public_key_size > 0) && (public_key != NULL)) {
        layer_ctx->is_external_pub_key_provided = true;
        /* Copy the public key provided */
        memcpy(&layer_ctx->data.attest_pub_key[0],
               public_key,
               public_key_size);
        layer_ctx->data.attest_pub_key_len = public_key_size;

        /* If public key is provided, then provided label (if any) is ignored */
        layer_ctx->data.attest_key_label_len = 0;

    } else {
        /* No external public key is provided */
        layer_ctx->is_external_pub_key_provided = false;

        if ((label_size > 0) && (label != NULL)) {
            /* Copy the label provided */
            memcpy(&layer_ctx->data.attest_key_label[0],
                   label,
                   label_size);
            layer_ctx->data.attest_key_label_len = label_size;

        } else {
            layer_ctx->data.attest_key_label_len = 0;
        }
    }

    /* Correct layer should already be assigned in last call of
     * derive child command
     */
    /* Finalise the current layer & create leaf certificate */
    err = create_layer_certificate(input_layer_idx);
    if (err != DPE_NO_ERROR) {
        return err;
    }

    /* Get parent layer derived public key to verify the certificate signature */
    parent_layer_idx = layer_ctx_array[input_layer_idx].parent_layer_idx;
    assert(parent_layer_idx < MAX_NUM_OF_LAYERS);
    parent_layer_ctx = &layer_ctx_array[parent_layer_idx];

    if (derived_public_key_buf_size < sizeof(parent_layer_ctx->data.attest_pub_key)) {
        return DPE_INVALID_ARGUMENT;
    }

    memcpy(derived_public_key_buf,
           &parent_layer_ctx->data.attest_pub_key[0],
           parent_layer_ctx->data.attest_pub_key_len);
    *derived_public_key_actual_size = parent_layer_ctx->data.attest_pub_key_len;

    /* Get certificate chain */
    err = get_certificate_chain(input_layer_idx,
                                certificate_chain_buf,
                                certificate_chain_buf_size,
                                certificate_chain_actual_size);
    if (err != DPE_NO_ERROR) {
        return err;
    }

    log_certificate_chain(certificate_chain_buf, *certificate_chain_actual_size);

    /* Renew handle for the same context */
    *new_context_handle = input_ctx_handle;
    status = renew_nonce(new_context_handle);
    if (status != PSA_SUCCESS) {
        return DPE_INTERNAL_ERROR;
    }
    component_ctx_array[input_ctx_idx].nonce = GET_NONCE(*new_context_handle);

    /* Clear the context label and key contents */
    memset(&layer_ctx->data.attest_key_label[0], 0u, layer_ctx->data.attest_key_label_len);
    memset(&layer_ctx->data.attest_pub_key[0], 0u, layer_ctx->data.attest_pub_key_len);

    return DPE_NO_ERROR;
}
