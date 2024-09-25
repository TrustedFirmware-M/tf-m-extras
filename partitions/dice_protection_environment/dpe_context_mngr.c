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
#define SEAL_CONTEXT_DATA_MAX_SIZE (DICE_HASH_SIZE       \
                                    + sizeof(DiceMode)   \
                                    + DICE_HIDDEN_SIZE)


static struct component_context_t component_ctx_array[MAX_NUM_OF_COMPONENTS];
static struct cert_context_t cert_ctx_array[MAX_NUM_OF_CERTIFICATES];

static dpe_error_t store_linked_component(struct cert_context_t *cert_ctx,
                                          struct component_context_t *comp_ctx)
{
    if (cert_ctx->linked_components.count >=
            ARRAY_SIZE(cert_ctx->linked_components.ptr)) {
        /* linked_components.ctx[] is full */
        return DPE_INSUFFICIENT_MEMORY;
    }

    cert_ctx->linked_components.ptr[cert_ctx->linked_components.count] = comp_ctx;
    cert_ctx->linked_components.count++;

    return DPE_NO_ERROR;
}

static void remove_linked_component(struct cert_context_t *cert_ctx,
                                    const struct component_context_t *comp_ctx)
{
    int i, pos;

    /* Find the position of the input component */
    for (i = 0; i < ARRAY_SIZE(cert_ctx->linked_components.ptr); i++) {
        if (cert_ctx->linked_components.ptr[i] == comp_ctx) {
            pos = i;
            break;
        }
    }

    assert(i < ARRAY_SIZE(cert_ctx->linked_components.ptr));

    /* Left shift remaining elements by 1 from current position */
    for(i = pos; i < ARRAY_SIZE(cert_ctx->linked_components.ptr) - 1; i++) {
        cert_ctx->linked_components.ptr[i] = cert_ctx->linked_components.ptr[i + 1];
    }
    cert_ctx->linked_components.ptr[i] = NULL;
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

static struct cert_context_t * get_free_certificate_context(void)
{
    int i;

    for (i = 0; i < MAX_NUM_OF_CERTIFICATES; i++) {
        if (cert_ctx_array[i].state == CERT_CTX_UNASSIGNED) {
            cert_ctx_array[i].state = CERT_CTX_ASSIGNED;
            return &cert_ctx_array[i];
        }
    }

    return NULL;
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

static void set_context_to_default(struct component_context_t *comp_ctx)
{
    comp_ctx->in_use = false;
    /* Allow component to be derived by default */
    comp_ctx->is_allowed_to_derive = true;
    /* export CDI attribute is inherited and once disabled, a derived context
     * and subsequent derivations cannot export CDI, hence enable by default
     */
    comp_ctx->is_export_cdi_allowed = true;
    comp_ctx->is_cert_id_supplied = false;
    comp_ctx->is_cdi_created = false;
    comp_ctx->nonce = INVALID_NONCE_VALUE;
    comp_ctx->parent_comp_ctx = NULL;
    comp_ctx->linked_cert_ctx = NULL;
    (void)memset(&comp_ctx->data, 0, sizeof(struct component_context_data_t));
    comp_ctx->target_locality = DEFAULT_TARGET_LOCALITY;
}

static void initialise_certificate_context(struct cert_context_t *cert_ctx)
{
    int j;

    cert_ctx->parent_cert_ptr = NULL;
    cert_ctx->state = CERT_CTX_UNASSIGNED;
    cert_ctx->parent_cert_ptr = NULL;
    cert_ctx->is_cdi_to_be_exported = false;
    cert_ctx->is_rot_cert_ctx = false;
    cert_ctx->cert_id = DPE_CERT_ID_INVALID;
    (void)memset(&cert_ctx->attest_cdi_hash_input, 0,
                 sizeof(cert_ctx->attest_cdi_hash_input));
    (void)memset(&cert_ctx->data, 0, sizeof(struct cert_context_data_t));
    cert_ctx->data.attest_cdi_key_id = PSA_KEY_ID_NULL;
    cert_ctx->data.seal_cdi_key_id = PSA_KEY_ID_NULL;
    cert_ctx->data.attest_key_id = PSA_KEY_ID_NULL;
    cert_ctx->linked_components.count = 0;
    for (j = 0; j < ARRAY_SIZE(cert_ctx->linked_components.ptr); j++) {
        cert_ctx->linked_components.ptr[j] = NULL;
    }
}

static void free_certificate_context(struct cert_context_t *cert_ctx)
{
    destroy_certificate_context_keys(cert_ctx);
    initialise_certificate_context(cert_ctx);
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

/* Seal_CDI Input requires {authority, mode, hidden} in same order */
static psa_status_t get_component_data_for_seal_cdi(uint8_t *dest_buf,
                                                    size_t max_size,
                                                    size_t *dest_size,
                                                    const struct component_context_t *comp_ctx)
{
    size_t out_size = 0;

    if ((DICE_HASH_SIZE + sizeof(comp_ctx->data.mode) + DICE_HIDDEN_SIZE) > max_size) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

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
    int i;
    uint16_t num_of_linked_components;
    struct component_context_t *comp_ctx;

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
        comp_ctx = cert_ctx->linked_components.ptr[i];
        status = get_component_data_for_attest_cdi(component_ctx_data,
                                                   sizeof(component_ctx_data),
                                                   &ctx_data_size,
                                                   comp_ctx);
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

static psa_status_t compute_seal_cdi_input(struct cert_context_t *cert_ctx)
{
    psa_status_t status;
    uint8_t seal_ctx_data[SEAL_CONTEXT_DATA_MAX_SIZE];
    size_t ctx_data_size, hash_len;
    uint16_t i, num_of_linked_components;
    struct component_context_t *comp_ctx;

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
        comp_ctx = cert_ctx->linked_components.ptr[i];
        status = get_component_data_for_seal_cdi(seal_ctx_data,
                                                 sizeof(seal_ctx_data),
                                                 &ctx_data_size,
                                                 comp_ctx);
        if (status != PSA_SUCCESS) {
            goto exit;
        }

        status = psa_hash_update(&hash_op,
                                 seal_ctx_data,
                                 ctx_data_size);
        if (status != PSA_SUCCESS) {
            goto exit;
        }
    }

    status = psa_hash_finish(&hash_op,
                             &cert_ctx->seal_cdi_hash_input[0],
                             sizeof(cert_ctx->seal_cdi_hash_input),
                             &hash_len);

    assert(hash_len == DPE_HASH_ALG_SIZE);

exit:
    if (status != PSA_SUCCESS) {
        psa_hash_abort(&hash_op);
    }

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

static dpe_error_t prepare_certificate(struct cert_context_t *cert_ctx)
{
    psa_status_t status;
    struct cert_context_t *parent_cert_ctx;

    parent_cert_ctx = cert_ctx->parent_cert_ptr;
    assert(parent_cert_ctx != NULL);

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

        status = compute_seal_cdi_input(cert_ctx);
        if (status != PSA_SUCCESS) {
            return DPE_INTERNAL_ERROR;
        }

        status = derive_seal_cdi(cert_ctx, parent_cert_ctx);
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

static bool is_cert_id_used(uint32_t cert_id, struct cert_context_t **cert_ctx)
{
    int i;

    for (i = 0; i < MAX_NUM_OF_CERTIFICATES; i++) {
        if (cert_ctx_array[i].cert_id == cert_id) {
            *cert_ctx = &cert_ctx_array[i];
            return true;
        }
    }

    /* No certificate ID match found */
    return false;
}

/*
 * \brief When cert_id is supplied, assign a certificate context to the component
 *
 * \param[in]  new_ctx        Pointer to input component context.
 * \param[in]  cert_id        Input certificate ID.
 *
 * Notes: If a cert_id is not used, and its value is not "DPE_CERT_ID_SAME_AS_PARENT",
 *        create a new certificate context and assign it to input component.
 *        If a cert_id is already used and that certificate is not created/finalised,
 *        assign that certificate context to the input component.
 *        If a cert_id value is "DPE_CERT_ID_SAME_AS_PARENT", assign the
 *        parent component's certificate to the input component
 *
 * \return Returns error code of type dpe_error_t
 */
static dpe_error_t
assign_component_to_certificate_with_cert_id(struct component_context_t *new_ctx,
                                             uint32_t cert_id)
{
    struct cert_context_t *parent_cert_ctx, *cert_ctx_to_link = NULL;

    assert(new_ctx->parent_comp_ctx != NULL);

    parent_cert_ctx = new_ctx->parent_comp_ctx->linked_cert_ctx;
    assert(parent_cert_ctx != NULL);

    /* Cert_id was sent by the client */
    if (cert_id == DPE_CERT_ID_SAME_AS_PARENT) {
        if (parent_cert_ctx->state == CERT_CTX_FINALISED) {
            /* Cannot add to the certificate context which is already finalised */
            return DPE_INTERNAL_ERROR;
        }
        /* Derived context belongs to the same certificate as its parent component */
        new_ctx->linked_cert_ctx = parent_cert_ctx;

    } else if (is_cert_id_used(cert_id, &cert_ctx_to_link)) {
        /* Cert_id is already in use but certificate context must be assigned, because
            * cert_id is invalidated when certificate context gets finalised.
            */
        assert(cert_ctx_to_link->state != CERT_CTX_FINALISED);

        /* Use the same certificate context that is associated with cert_id */
        new_ctx->linked_cert_ctx = cert_ctx_to_link;
        /* Linked certificate context's parent is already assigned */

    } else {
        /* Get new certificate context and link derived context to it */
        cert_ctx_to_link = get_free_certificate_context();
        if (cert_ctx_to_link == NULL) {
            return DPE_INSUFFICIENT_MEMORY;
        }
        /* Link this context to the new certificate context */
        new_ctx->linked_cert_ctx = cert_ctx_to_link;
        /* New certificate context's parent is parent component's certificate context */
        cert_ctx_to_link->parent_cert_ptr = parent_cert_ctx;
        cert_ctx_to_link->cert_id = cert_id;
    }

    return DPE_NO_ERROR;
}

/*
 * \brief When cert_id is NOT supplied, all components to be included in a new
 *        certificate are found by traversing backwards till a certificate is
 *        already created for a component.
 *
 * \param[in]  comp_ctx       Pointer to input component context.
 * \param[in]  cert_ctx       Pointer to certificate context.
 *
 * \return Returns error code of type dpe_error_t
 */
static dpe_error_t
assign_components_to_certificate(struct component_context_t *comp_ctx,
                                 struct cert_context_t *cert_ctx)
{
    dpe_error_t err;

    /* Get all the linked components for this certificate */
    /* Traverse the tree backwards until a component is represented by
     * a certificate (i.e. its CDI is created)
     */
    while (!comp_ctx->is_cdi_created) {

        /* Link this context to the new certificate context */
        comp_ctx->linked_cert_ctx = cert_ctx;
        /* Also, store this component in certificate context */
        err = store_linked_component(cert_ctx, comp_ctx);
        IF_DPE_ERROR_RETURN(err);

        if (comp_ctx == comp_ctx->parent_comp_ctx) {
            /* We have reached to the first/root component in the tree */
            break;
        }
        /* Move to parent component context */
        comp_ctx = comp_ctx->parent_comp_ctx;
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
    psa_key_id_t rot_cdi_key_id;
    struct component_context_t *rot_comp_ctx = &component_ctx_array[0];
    struct cert_context_t *rot_cert_ctx = &cert_ctx_array[0];

    rot_cert_ctx->is_rot_cert_ctx = true;
    rot_cert_ctx->parent_cert_ptr = NULL;
    /* Get the RoT CDI key for the RoT certificate */
    rot_cdi_key_id = dpe_plat_get_rot_cdi_key_id();
    rot_cert_ctx->data.attest_cdi_key_id = rot_cdi_key_id;
    /* Same CDI to be used for further derivation */
    rot_cert_ctx->data.seal_cdi_key_id = rot_cdi_key_id;
    /* Init RoT context, ready to be derived in next call to DeriveContext */
    rot_comp_ctx->nonce = 0;
    /* Set the target locality for RoT context */
    rot_comp_ctx->target_locality = LOCALITY_RSE_S;
    /* Parent component for derived RoT context is same.
     * It is not set to NULL as later on when creating certificate and
     * parent_comp_ctx pointer is checked against NULL value */
    rot_comp_ctx->parent_comp_ctx = rot_comp_ctx;
    /* Link context to RoT certificate */
    rot_comp_ctx->linked_cert_ctx = rot_cert_ctx;
    rot_comp_ctx->expected_mhu_id = 0;
    *rot_ctx_handle = 0; /* index = 0, nonce = 0 */

    return DPE_NO_ERROR;
}

dpe_error_t initialise_context_mngr(int *rot_ctx_handle)
{
    int i;

    for (i = 0; i < MAX_NUM_OF_COMPONENTS; i++) {
        set_context_to_default(&component_ctx_array[i]);
    }

    for (i = 0; i < MAX_NUM_OF_CERTIFICATES; i++) {
        initialise_certificate_context(&cert_ctx_array[i]);
    }

    return create_rot_context(rot_ctx_handle);
}

static void free_certificate_context_if_empty(struct cert_context_t *cert_ctx)
{
    if (cert_ctx->linked_components.count == 0) {
        free_certificate_context(cert_ctx);
    }
}

static struct cert_context_t *
get_parent_cert_ctx(struct component_context_t *comp_ctx)
{
    /* Traverse the tree backwards until a component is represented by
     * a certificate (i.e. its CDI is created)
     */
    do {
        if (comp_ctx == comp_ctx->parent_comp_ctx) {
            /* We have reached to the first/root component in the tree */
            break;
        }
        /* Move to parent component context */
        comp_ctx = comp_ctx->parent_comp_ctx;
    } while (!comp_ctx->is_cdi_created);

    /* We are now pointing to parent component in the backwards chain where
     * CDI is created. This represents parent certificate for current context.
     */
    return comp_ctx->linked_cert_ctx;
}

static dpe_error_t
validate_derive_context_inputs(int input_ctx_handle,
                               bool create_certificate,
                               const DiceInputValues *dice_inputs,
                               int32_t client_id,
                               bool allow_new_context_to_export,
                               bool export_cdi)
{
    struct component_context_t *parent_ctx;
    uint16_t parent_ctx_idx;

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

    if (export_cdi &&
       (!parent_ctx->is_export_cdi_allowed || !allow_new_context_to_export)) {
        return DPE_INVALID_ARGUMENT;
    }

    return DPE_NO_ERROR;
}

static dpe_error_t
populate_component(struct component_context_t *parent_ctx,
                   struct component_context_t *derived_ctx,
                   bool allow_new_context_to_derive,
                   const DiceInputValues *dice_inputs,
                   int32_t target_locality,
                   bool allow_new_context_to_export)

{
    dpe_error_t err;

    if (parent_ctx->is_export_cdi_allowed && allow_new_context_to_export) {
        /* If parent context has export enabled and input allow_new_context_to_export
         * is true, then allow context CDI to be exported for derived context
         */
        derived_ctx->is_export_cdi_allowed = true;
    } else {
        /* Export of new context CDI is NOT allowed */
        derived_ctx->is_export_cdi_allowed = false;
    }

    /* Copy dice input to the new derived component context */
    err = copy_dice_input(derived_ctx, dice_inputs);
    if (err != DPE_NO_ERROR) {
        return err;
    }
    derived_ctx->target_locality = target_locality;

    /* Update parent component in new derived component context */
    derived_ctx->parent_comp_ctx = parent_ctx;
    /* Mark new derived component index as in use */
    derived_ctx->in_use = true;
    derived_ctx->is_allowed_to_derive = allow_new_context_to_derive;

    return DPE_NO_ERROR;
}

/*
 * \brief Handle certificate request, when cert_id is supplied
 *
 * \return Returns error code of type dpe_error_t
 */
static dpe_error_t
process_certificate_request_with_cert_id(struct component_context_t *derived_ctx,
                                         uint32_t cert_id,
                                         bool create_certificate,
                                         bool export_cdi,
                                         bool return_certificate,
                                         uint8_t *new_certificate_buf,
                                         size_t new_certificate_buf_size,
                                         size_t *new_certificate_actual_size,
                                         uint8_t *exported_cdi_buf,
                                         size_t exported_cdi_buf_size,
                                         size_t *exported_cdi_actual_size)
{
    dpe_error_t err;
    struct cert_context_t *cert_ctx = NULL;

    derived_ctx->is_cert_id_supplied = true;
    /* Mark the cdi creation for all context as cert_id is supplied */
    derived_ctx->is_cdi_created = true;
    /* Assign certificate to the component */
    err = assign_component_to_certificate_with_cert_id(derived_ctx, cert_id);
    IF_DPE_ERROR_RETURN(err);

    cert_ctx = derived_ctx->linked_cert_ctx;
    assert(cert_ctx != NULL);
    err = store_linked_component(cert_ctx, derived_ctx);
    IF_DPE_ERROR_RETURN(err);
    if (create_certificate) {
        cert_ctx->is_cdi_to_be_exported = export_cdi;

        /* Finalise the certificate context */
        cert_ctx->state = CERT_CTX_FINALISED;
        cert_ctx->cert_id = DPE_CERT_ID_INVALID; /* make same cert_id reusable */
        err = prepare_certificate(cert_ctx);
        IF_DPE_ERROR_RETURN(err);

        if (return_certificate) {
            /* Encode and return generated certificate */
            err = encode_certificate(cert_ctx,
                                     new_certificate_buf,
                                     new_certificate_buf_size,
                                     new_certificate_actual_size);
            IF_DPE_ERROR_RETURN(err);
        }

        if (export_cdi) {
            err = get_encoded_cdi_to_export(cert_ctx,
                                            exported_cdi_buf,
                                            exported_cdi_buf_size,
                                            exported_cdi_actual_size);
            IF_DPE_ERROR_RETURN(err);
        }
    }

    return DPE_NO_ERROR;
}

/*
 * \brief Handle certificate request, when cert_id is NOT supplied
 *
 * \return Returns error code of type dpe_error_t
 */
static dpe_error_t
process_certificate_request(struct component_context_t *derived_ctx,
                            struct component_context_t *parent_ctx,
                            bool create_certificate,
                            bool export_cdi,
                            bool return_certificate,
                            uint8_t *new_certificate_buf,
                            size_t new_certificate_buf_size,
                            size_t *new_certificate_actual_size,
                            uint8_t *exported_cdi_buf,
                            size_t exported_cdi_buf_size,
                            size_t *exported_cdi_actual_size)
{
    dpe_error_t err;
    struct cert_context_t *cert_ctx = NULL;

    derived_ctx->is_cert_id_supplied = false;
    /* Certificate context will be assigned when create_certificate = true */

    if (create_certificate) {
        /* Assign new certificate context and link derived context to it */
        cert_ctx = get_free_certificate_context();
        if (cert_ctx == NULL) {
            return DPE_INSUFFICIENT_MEMORY;
        }
        cert_ctx->parent_cert_ptr = get_parent_cert_ctx(derived_ctx);
        assert(cert_ctx->parent_cert_ptr != NULL);

        err = assign_components_to_certificate(derived_ctx, cert_ctx);
        IF_DPE_ERROR_RETURN(err);

        cert_ctx->is_cdi_to_be_exported = export_cdi;
        /* Finalise the certificate context */
        cert_ctx->state = CERT_CTX_FINALISED;
        err = prepare_certificate(cert_ctx);
        IF_DPE_ERROR_RETURN(err);

        /* Mark the cdi creation for this context as cert_id is supplied */
        derived_ctx->is_cdi_created = true;

        if (return_certificate) {
            /* Encode and return generated certificate */
            err = encode_certificate(cert_ctx,
                                     new_certificate_buf,
                                     new_certificate_buf_size,
                                     new_certificate_actual_size);
            IF_DPE_ERROR_RETURN(err);
        }

        if (export_cdi) {
            err = get_encoded_cdi_to_export(cert_ctx,
                                            exported_cdi_buf,
                                            exported_cdi_buf_size,
                                            exported_cdi_actual_size);
            IF_DPE_ERROR_RETURN(err);
        }
    }

    return DPE_NO_ERROR;
}

static dpe_error_t
check_if_mixing_custom_params(uint32_t cert_id,
                              struct component_context_t *parent_ctx)
{
    bool is_cert_id_supplied = (cert_id != DPE_CERT_ID_INVALID);

    if ((parent_ctx->parent_comp_ctx == parent_ctx) ||
        (is_cert_id_supplied == parent_ctx->is_cert_id_supplied)) {
        /* Deriving 1st context OR no mixing of arguments  */
        return DPE_NO_ERROR;
    }

    /* So now,
     * is_cert_id_supplied != parent_ctx->is_cert_id_supplied (mixed commands)
     */
    if ((parent_ctx->linked_cert_ctx == NULL) ||
        (parent_ctx->linked_cert_ctx->state != CERT_CTX_FINALISED))  {
        /* Condition 1: parent_ctx (w/o cert_id) -> new_ctx (with cert_id)
         * Since parent_ctx is derived w/o cert_id, it has no linked_cert_ctx;
         * Condition 2: parent_ctx (with cert_id -> new_ctx (w/o cert_id)
         * Since parent_ctx is derived with cert_id, it has linked_cert_ctx
         * but if it is not finalised, then return error
         */
        return DPE_INVALID_ARGUMENT;
    }

    return DPE_NO_ERROR;
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
    uint16_t parent_ctx_idx;
    int free_component_idx;

    log_derive_context(input_ctx_handle, cert_id, retain_parent_context,
                       allow_new_context_to_derive, create_certificate, dice_inputs,
                       client_id);

    err = validate_derive_context_inputs(input_ctx_handle,
                                         create_certificate,
                                         dice_inputs,
                                         client_id,
                                         allow_new_context_to_export,
                                         export_cdi);
    IF_DPE_ERROR_RETURN(err);

    /* Get parent component index from the input handle */
    parent_ctx_idx = GET_IDX(input_ctx_handle);
    parent_ctx = &component_ctx_array[parent_ctx_idx];

    err = check_if_mixing_custom_params(cert_id, parent_ctx);
    IF_DPE_ERROR_RETURN(err);

    /* Get next free component index to add new derived context */
    free_component_idx = get_free_component_context_index();
    if (free_component_idx < 0) {
        return DPE_INSUFFICIENT_MEMORY;
    }

    derived_ctx = &component_ctx_array[free_component_idx];
    /* Copy input component*/
    err = populate_component(parent_ctx,
                             derived_ctx,
                             allow_new_context_to_derive,
                             dice_inputs,
                             target_locality,
                             allow_new_context_to_export);
    IF_DPE_ERROR_RETURN(err);

    if (cert_id != DPE_CERT_ID_INVALID) {
        /* Cert_id was sent by the client */
        err = process_certificate_request_with_cert_id(derived_ctx,
                                                       cert_id,
                                                       create_certificate,
                                                       export_cdi,
                                                       return_certificate,
                                                       new_certificate_buf,
                                                       new_certificate_buf_size,
                                                       new_certificate_actual_size,
                                                       exported_cdi_buf,
                                                       exported_cdi_buf_size,
                                                       exported_cdi_actual_size);
        IF_DPE_ERROR_GO_TO_CLEAN_UP_AND_EXIT(err);

    } else {
        /* Cert id was NOT sent by the client */
        err = process_certificate_request(derived_ctx,
                                          parent_ctx,
                                          create_certificate,
                                          export_cdi,
                                          return_certificate,
                                          new_certificate_buf,
                                          new_certificate_buf_size,
                                          new_certificate_actual_size,
                                          exported_cdi_buf,
                                          exported_cdi_buf_size,
                                          exported_cdi_actual_size);
        IF_DPE_ERROR_GO_TO_CLEAN_UP_AND_EXIT(err);
    }

    if (retain_parent_context) {
        /* Retain and return parent handle with renewed nonce */
        *new_parent_context_handle = input_ctx_handle;
        err = renew_nonce(new_parent_context_handle);
        IF_DPE_ERROR_GO_TO_CLEAN_UP_AND_EXIT(err);
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
        IF_DPE_ERROR_GO_TO_CLEAN_UP_AND_EXIT(err);
        /* Update nonce in new derived component context */
        derived_ctx->nonce = GET_NONCE(*new_context_handle);

    } else {
        /* Return invalid handle if cdi is exported */
        *new_context_handle = INVALID_HANDLE;
        derived_ctx->nonce = INVALID_NONCE_VALUE;
    }

    log_derive_context_output(new_context_handle,
                              new_parent_context_handle,
                              derived_ctx,
                              free_component_idx,
                              derived_ctx->linked_cert_ctx,
                              new_certificate_buf,
                              new_certificate_actual_size);

    return DPE_NO_ERROR;

clean_up_and_exit:
    set_context_to_default(derived_ctx);
    if (derived_ctx->linked_cert_ctx != NULL) {
        free_certificate_context_if_empty(derived_ctx->linked_cert_ctx);
    }

    return err;
}

static unsigned int
check_if_component_is_linked_to_certificate(struct component_context_t *comp_ctx,
                                            struct cert_context_t **cert_ctx)
{
    int i, j, match_count;

    match_count = 0;

    for (i = 0; i < MAX_NUM_OF_CERTIFICATES; i++) {
        for (j = 0; j < cert_ctx_array[i].linked_components.count; j++) {

            if (cert_ctx_array[i].linked_components.ptr[j] == comp_ctx) {
                /* Component is referenced in a certificate */
                match_count++;

                if (match_count == 1) {
                    /* Store the first match only */
                    *cert_ctx = &cert_ctx_array[i];
                }
            }
        }
    }

    return match_count;
}

static dpe_error_t
destroy_context_with_cert_id(struct component_context_t *comp_ctx,
                             bool destroy_recursively)
{
    struct cert_context_t *cert_ctx;

    cert_ctx = comp_ctx->linked_cert_ctx;
    assert(cert_ctx != NULL);

#ifndef DPE_TEST_MODE
    //TODO: Prevent destruction of context if it belongs to RoT, Platform, AP FW
    //      or any platform configuration dependent certificate.
#endif /* !DPE_TEST_MODE */

    if (!destroy_recursively) {
        set_context_to_default(comp_ctx);
        remove_linked_component(cert_ctx, comp_ctx);
    } else {
        //TODO: To be implemented
        return DPE_INVALID_ARGUMENT;
    }

    /* Free the certificate context if all of its components are destroyed */
    free_certificate_context_if_empty(cert_ctx);

    return DPE_NO_ERROR;
}

static dpe_error_t
destroy_context(struct component_context_t *comp_ctx,
                bool destroy_recursively)
{
    uint16_t linked_cert_count;
    struct cert_context_t *cert_ctx = NULL;

    if (!destroy_recursively) {
        /* Check how many certificates include the input component */
        linked_cert_count =
                check_if_component_is_linked_to_certificate(comp_ctx, &cert_ctx);
        if (linked_cert_count > 1) {
            /* Cannot destroy a component which is part of multiple certificates */
            return DPE_INVALID_ARGUMENT;
        }

        set_context_to_default(comp_ctx);
        if (linked_cert_count == 1) {
            /* Component was linked to only one certificate, hence remove it */
            free_certificate_context(cert_ctx);
        }

    } else {
        //TODO: To be implemented
        return DPE_INVALID_ARGUMENT;
    }

    return DPE_NO_ERROR;
}

dpe_error_t destroy_context_request(int input_ctx_handle,
                                    bool destroy_recursively)
{
    uint16_t comp_ctx_idx;
    struct component_context_t *comp_ctx;

    log_destroy_context(input_ctx_handle, destroy_recursively);

    /* Validate input handle */
    if (!is_input_handle_valid(input_ctx_handle)) {
        return DPE_INVALID_ARGUMENT;
    }

    /* Get component index from the input handle */
    comp_ctx_idx = GET_IDX(input_ctx_handle);
    comp_ctx = &component_ctx_array[comp_ctx_idx];

    //TODO: Do NOT allow parent context to be destroyed if it has children and
    // destroy_recursively is not requested

    if (comp_ctx->is_cert_id_supplied) {
        return destroy_context_with_cert_id(comp_ctx,
                                            destroy_recursively);
    } else {
        return destroy_context(comp_ctx,
                               destroy_recursively);
    }
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
    uint16_t comp_ctx_idx;
    dpe_error_t err;
    psa_status_t status;
    struct component_context_t *comp_ctx;
    struct cert_context_t *parent_cert_ctx, *cert_ctx;
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
    comp_ctx_idx = GET_IDX(input_ctx_handle);
    comp_ctx = &component_ctx_array[comp_ctx_idx];

    if (comp_ctx->is_cert_id_supplied) {
        /* Get current linked certificate context */
        cert_ctx = comp_ctx->linked_cert_ctx;
        assert(cert_ctx != NULL);

        if (cert_ctx->state == CERT_CTX_FINALISED) {
            /* Input certificate context is finalised,
             * new leaf certificate context is its child now
             */
            leaf_cert_ctx.parent_cert_ptr = cert_ctx;
            /* Linked components count already initialised to 0 */

        } else {
            /* Input certificate context is not finalised,
             * new leaf certificate context share the same components as in the
             * input certificate context
             */
            memcpy(&leaf_cert_ctx.linked_components, &cert_ctx->linked_components,
                    sizeof(cert_ctx->linked_components));
            leaf_cert_ctx.parent_cert_ptr = cert_ctx->parent_cert_ptr;
        }

    } else {
        if (comp_ctx->is_cdi_created) {
            /* New leaf certificate will have no components */
            /* Get current linked certificate context */
            cert_ctx = comp_ctx->linked_cert_ctx;
            assert(cert_ctx != NULL);
            /* Leaf certificate will be its child now */
            leaf_cert_ctx.parent_cert_ptr = cert_ctx;

        } else {
            /* Traverse the tree and get all the components till last CDI was set */
            err = assign_components_to_certificate(comp_ctx,
                                                   &leaf_cert_ctx);
            IF_DPE_ERROR_RETURN(err);

            leaf_cert_ctx.parent_cert_ptr = get_parent_cert_ctx(comp_ctx);
            assert(leaf_cert_ctx.parent_cert_ptr != NULL);
        }
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
    parent_cert_ctx = leaf_cert_ctx.parent_cert_ptr;
    assert(parent_cert_ctx != NULL);

    /* Correct certificate context should already be assigned in last call of
     * derive context command
     */
    /* Create leaf certificate */
    err = prepare_certificate(&leaf_cert_ctx);
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
        comp_ctx->nonce = GET_NONCE(*new_context_handle);

    } else {
        *new_context_handle = INVALID_HANDLE;
        comp_ctx->nonce = INVALID_NONCE_VALUE;
    }

    log_certify_key_output_handle(*new_context_handle);
    log_intermediate_certificate(certificate_buf,
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
    uint16_t comp_ctx_idx;
    psa_status_t status;
    struct cert_context_t *cert_ctx;
    struct component_context_t *comp_ctx;

    log_get_certificate_chain(input_ctx_handle, retain_context,
                              clear_from_context, certificate_chain_buf_size);

    /* Validate input handle */
    if (!is_input_handle_valid(input_ctx_handle)) {
        return DPE_INVALID_ARGUMENT;
    }

    /* Get component index from the input handle */
    comp_ctx_idx = GET_IDX(input_ctx_handle);
    comp_ctx = &component_ctx_array[comp_ctx_idx];

    if (comp_ctx->is_cert_id_supplied) {
        /* Get current linked certificate context idx */
        cert_ctx = comp_ctx->linked_cert_ctx;
        assert(cert_ctx != NULL);
        if (cert_ctx->state != CERT_CTX_FINALISED) {
            /* If the context has accumulated info and not yet part of a certificate,
             * return an invalid-argument error
             */
            return DPE_INVALID_ARGUMENT;
        }

    } else {
        if (!comp_ctx->is_cdi_created) {
            /* If the context has accumulated info and not yet part of a certificate,
             * return an invalid-argument error
             */
            return DPE_INVALID_ARGUMENT;
        }
        /* Get current linked certificate context idx */
        cert_ctx = comp_ctx->linked_cert_ctx;
        assert(cert_ctx != NULL);
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
        comp_ctx->nonce = GET_NONCE(*new_context_handle);

        if (clear_from_context) {
        //TODO: Reimplement the clear_from_context functionality after memory
        //      optimization; Certificates are not ready made and they are not
        //      stored in the certificate context anymore. They are created on-the-fly
        //      when requested. Add a test as well.
        }

    } else {
        *new_context_handle = INVALID_HANDLE;
        comp_ctx->nonce = INVALID_NONCE_VALUE;
    }
    log_get_certificate_chain_output_handle(*new_context_handle);

    return DPE_NO_ERROR;
}
