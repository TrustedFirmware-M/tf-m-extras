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
#include "dpe_log.h"
#include "psa/crypto.h"

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
        status = psa_hash_compute(PSA_ALG_SHA_256,
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

static dpe_error_t derive_child_create_certificate(uint16_t curr_idx)
{
    //TODO: Implementation pending
    /* Finalise the layer */
    layer_ctx_array[curr_idx].state = LAYER_STATE_FINALISED;
    return DPE_NO_ERROR;
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

    return INVALID_LAYER_IDX;
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
    /* Parent is same as child for RoT context */
    child_comp_ctx->parent_idx = 0;
    /* Parent not deriving any more children */
    invalidate_handle(new_parent_ctx_handle);

    //TODO: Update expected_mhu_id of derived child
    /* Create certificate for RoT layer */
    status = derive_child_create_certificate(DPE_ROT_LAYER_IDX);
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

static void assign_layer_to_context(struct component_context_t *new_ctx)
{
    uint16_t new_layer_idx, parent_layer_idx;

    assert(new_ctx->parent_idx < MAX_NUM_OF_COMPONENTS);

    parent_layer_idx = component_ctx_array[new_ctx->parent_idx].linked_layer_idx;
    assert(parent_layer_idx < MAX_NUM_OF_LAYERS);

    if (layer_ctx_array[parent_layer_idx].state == LAYER_STATE_FINALISED) {
        /* Parent comp's layer of new child is finalised; open a new layer */
        new_layer_idx = open_new_layer();
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
    dpe_error_t status;
    struct component_context_t *child_ctx, *parent_ctx, *new_ctx;
    uint16_t input_child_idx, input_parent_idx;

#ifdef TFM_S_REG_TEST
    if (layer_ctx_array[DPE_ROT_LAYER_IDX].state != LAYER_STATE_FINALISED) {
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
    status = copy_dice_input(child_ctx, dice_inputs);
    if (status != DPE_NO_ERROR) {
        return status;
    }

    if (create_certificate) {
        status = derive_child_create_certificate(child_ctx->linked_layer_idx);
        if (status != DPE_NO_ERROR) {
            return status;
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
        assign_layer_to_context(new_ctx);

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
        assign_layer_to_context(new_ctx);

    } else {
        /* Parent not deriving any more children */
        /* No need to return parent handle */
        invalidate_handle(new_parent_ctx_handle);
        /* Renew nonce of parent context so it cannot be used again */
        parent_ctx->nonce = INVALID_NONCE_VALUE;
    }

    return DPE_NO_ERROR;
}
