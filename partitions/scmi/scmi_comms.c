/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 */

#include "psa/service.h"
#include "psa_manifest/scmi_comms.h"
#include "scmi_comms.h"
#include "scmi_hal.h"
#include "scmi_protocol.h"
#include "tfm_sp_log.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define SCMI_MESSAGE_HEADER_MESSAGE_ID_POS   0
#define SCMI_MESSAGE_HEADER_MESSAGE_ID_MASK \
    (UINT32_C(0xFF) << SCMI_MESSAGE_HEADER_MESSAGE_ID_POS)

#define SCMI_MESSAGE_HEADER_MESSAGE_TYPE_POS 8
#define SCMI_MESSAGE_HEADER_MESSAGE_TYPE_MASK \
    (UINT32_C(0x3) << SCMI_MESSAGE_HEADER_MESSAGE_TYPE_POS)

#define SCMI_MESSAGE_HEADER_PROTOCOL_ID_POS  10
#define SCMI_MESSAGE_HEADER_PROTOCOL_ID_MASK \
    (UINT32_C(0xFF) << SCMI_MESSAGE_HEADER_PROTOCOL_ID_POS)

#define SCMI_MESSAGE_HEADER_TOKEN_POS        18
#define SCMI_MESSAGE_HEADER_TOKEN_MASK \
    (UINT32_C(0x3FF) << SCMI_MESSAGE_HEADER_TOKEN_POS)

static uint32_t scmi_message_header(uint8_t message_id, uint8_t message_type,
                                    uint8_t protocol_id, uint8_t token)
{
    return (((uint32_t)message_id << SCMI_MESSAGE_HEADER_MESSAGE_ID_POS) &
            SCMI_MESSAGE_HEADER_MESSAGE_ID_MASK) |
           (((uint32_t)message_type << SCMI_MESSAGE_HEADER_MESSAGE_TYPE_POS) &
            SCMI_MESSAGE_HEADER_MESSAGE_TYPE_MASK) |
           (((uint32_t)protocol_id << SCMI_MESSAGE_HEADER_PROTOCOL_ID_POS) &
            SCMI_MESSAGE_HEADER_PROTOCOL_ID_MASK) |
           (((uint32_t)token << SCMI_MESSAGE_HEADER_TOKEN_POS) &
            SCMI_MESSAGE_HEADER_TOKEN_MASK);
}

#define TRANSPORT_BUFFER_STATUS_FREE_POS  0
#define TRANSPORT_BUFFER_STATUS_FREE_MASK \
    (UINT32_C(0x1) << TRANSPORT_BUFFER_STATUS_FREE_POS)

#define TRANSPORT_BUFFER_STATUS_ERROR_POS 1
#define TRANSPORT_BUFFER_STATUS_ERROR_MASK \
    (UINT32_C(0x1) << TRANSPORT_BUFFER_STATUS_ERROR_POS)

#define TRANSPORT_BUFFER_FLAGS_INTERRUPT_POS 0
#define TRANSPORT_BUFFER_FLAGS_INTERRUPT_MASK \
    (UINT32_C(0x1) << TRANSPORT_BUFFER_FLAGS_INTERRUPT_POS)

#define TRANSPORT_BUFFER_MAX_LENGTH \
    (SCP_SHARED_MEMORY_SIZE - offsetof(struct transport_buffer_t, message_header))

/**
 * \brief Shared memory area layout used for sending & receiving messages
 */
struct transport_buffer_t {
    uint32_t reserved0; /**< Reserved, must be zero */
    volatile uint32_t status; /**< Channel status */
    uint64_t reserved1; /**< Implementation defined field */
    uint32_t flags; /**< Channel flags */
    volatile uint32_t length; /**< Length in bytes of the message header and payload */
    uint32_t message_header; /**< Message header */
    uint32_t message_payload[]; /**< Message payload */
};

/**
 * \brief Structure representing an SCMI message.
 */
struct scmi_message_t {
    uint32_t header;
    uint32_t payload[(TRANSPORT_BUFFER_MAX_LENGTH - sizeof(uint32_t)) / sizeof(uint32_t)];
    uint32_t payload_len;
};

static struct transport_buffer_t *const shared_memory =
    (struct transport_buffer_t *)SCP_SHARED_MEMORY_BASE;

/**
 * \brief Initialize the SCMI transport layer.
 *
 * \return Error value as defined by scmi_comms_err_t.
 */
static scmi_comms_err_t transport_init(void)
{
    scmi_comms_err_t err;

    err = scmi_hal_doorbell_init();
    if (err != SCMI_COMMS_SUCCESS) {
        return err;
    }

    err = scmi_hal_shared_memory_init();
    if (err != SCMI_COMMS_SUCCESS) {
        return err;
    }

    shared_memory->flags = 0;
    shared_memory->length = 0;
    shared_memory->status = TRANSPORT_BUFFER_STATUS_FREE_MASK;

    return SCMI_COMMS_SUCCESS;
}

/**
 * \brief Read a message from the shared memory to the local buffer.
 *
 * \param[out] msg  SCMI message
 *
 * \return Error value as defined by scmi_comms_err_t.
 */
static scmi_comms_err_t transport_receive(struct scmi_message_t *msg)
{
    scmi_comms_err_t err = scmi_hal_doorbell_clear();
    if (err != SCMI_COMMS_SUCCESS) {
        return err;
    }

    uint32_t length = shared_memory->length;

    if ((length < sizeof(shared_memory->message_header)) ||
        (length > TRANSPORT_BUFFER_MAX_LENGTH)) {
        return SCMI_COMMS_INVALID_ARGUMENT;
    }

    memcpy(msg, &shared_memory->message_header, length);
    msg->payload_len = length - sizeof(msg->header);

    return SCMI_COMMS_SUCCESS;
}

/**
 * \brief Write a response from the local buffer to the shared memory and signal
 *        completion.
 *
 * \param[in] msg  SCMI message
 */
static void transport_respond(const struct scmi_message_t *msg)
{
    /* Populate shared memory area */
    memcpy(shared_memory->message_payload, msg->payload, msg->payload_len);
    shared_memory->length = msg->payload_len + sizeof(msg->header);

    /* Mark channel as free */
    shared_memory->status |= TRANSPORT_BUFFER_STATUS_FREE_MASK;

    /* TODO: Issue completion interrupt */
}

/**
 * \brief Write a message from the local buffer to the shared memory and wait
 *        for a response.
 *
 * \param[in] msg  SCMI message
 *
 * \return Error value as defined by scmi_comms_err_t.
 */
static int32_t transport_send(const struct scmi_message_t *msg)
{
    int32_t err;
    uint32_t length = msg->payload_len + sizeof(msg->header);

    if (length > TRANSPORT_BUFFER_MAX_LENGTH) {
        return SCMI_COMMS_INVALID_ARGUMENT;
    }

    /* Wait for channel to be free */
    /* TODO: Timeout */
    while (!(shared_memory->status & TRANSPORT_BUFFER_STATUS_FREE_MASK));

    /* Populate shared memory area */
    memcpy(&shared_memory->message_header, msg, length);
    shared_memory->length = length;

    /* Mark channel as busy */
    shared_memory->status &= ~TRANSPORT_BUFFER_STATUS_FREE_MASK;

    /* Ring doorbell */
    err = scmi_hal_doorbell_ring();
    if (err != SCMI_COMMS_SUCCESS) {
        return err;
    }

    /* Wait until channel is free */
    /* TODO: Wait for completion interrupt */
    while (!(shared_memory->status & TRANSPORT_BUFFER_STATUS_FREE_MASK));

    return SCMI_COMMS_SUCCESS;
}

/**
 * \brief Create an SCMI response containing only status.
 *
 * \param[out] msg     SCMI message
 * \param[in]  status  SCMI status
 */
static void scmi_response_status(struct scmi_message_t *msg, int32_t status)
{
    msg->payload[0] = status;
    msg->payload_len = sizeof(msg->payload[0]);
}

/**
 * \brief Create an SCMI system power state notify message.
 *
 * \param[out] msg  SCMI message
 */
static void scmi_message_sys_power_state_notify(struct scmi_message_t *msg)
{
    msg->header =
        scmi_message_header(SCMI_MESSAGE_ID_SYS_POWER_STATE_NOTIFY,
                            SCMI_MESSAGE_TYPE_COMMAND,
                            SCMI_PROTOCOL_ID_SYS_POWER_STATE,
                            0);

    assert(sizeof(struct scmi_sys_power_state_notify_t) <= sizeof(msg->payload));

    memcpy(msg->payload,
           &(struct scmi_sys_power_state_notify_t) { .notify_enable = 1 },
           sizeof(struct scmi_sys_power_state_notify_t));

    msg->payload_len = sizeof(struct scmi_sys_power_state_notify_t);
}

/**
 * \brief Handle an SCMI system power state set message.
 *
 * \param[in,out] msg  SCMI message
 */
static void scmi_handle_sys_power_state_set(struct scmi_message_t *msg)
{
    if (msg->payload_len != sizeof(struct scmi_sys_power_state_set_t)) {
        scmi_response_status(msg, SCMI_STATUS_PROTOCOL_ERROR);
        return;
    }

    struct scmi_sys_power_state_set_t *pwr_set =
        (struct scmi_sys_power_state_set_t *)msg->payload;

    int32_t status = scmi_hal_sys_power_state(0, pwr_set->flags, pwr_set->system_state);

    scmi_response_status(msg, status);
}

/**
 * \brief Handle an SCMI system power state notification.
 *
 * \param[in,out] msg  SCMI message
 */
static void scmi_handle_sys_power_state_notifier(struct scmi_message_t *msg)
{
    if (msg->payload_len != sizeof(struct scmi_sys_power_state_notifier_t)) {
        /* No return values for notifications */
        msg->payload_len = 0;
        return;
    }

    struct scmi_sys_power_state_notifier_t *pwr_not =
        (struct scmi_sys_power_state_notifier_t *)msg->payload;

    scmi_hal_sys_power_state(pwr_not->agent_id, pwr_not->flags, pwr_not->system_state);

    /* No return values for notifications */
    msg->payload_len = 0;
}

/**
 * \brief Handle a received SCMI message.
 *
 * \param[in,out] msg  SCMI message
 */
static void scmi_handle_message(struct scmi_message_t *msg)
{
    uint8_t message_id = (msg->header & SCMI_MESSAGE_HEADER_MESSAGE_ID_MASK)
                         >> SCMI_MESSAGE_HEADER_MESSAGE_ID_POS;
    uint8_t message_type = (msg->header & SCMI_MESSAGE_HEADER_MESSAGE_TYPE_MASK)
                           >> SCMI_MESSAGE_HEADER_MESSAGE_TYPE_POS;
    uint8_t protocol_id = (msg->header & SCMI_MESSAGE_HEADER_PROTOCOL_ID_MASK)
                          >> SCMI_MESSAGE_HEADER_PROTOCOL_ID_POS;

    if (protocol_id == SCMI_PROTOCOL_ID_SYS_POWER_STATE) {
        if (message_type == SCMI_MESSAGE_TYPE_COMMAND &&
            message_id == SCMI_MESSAGE_ID_SYS_POWER_STATE_SET) {
            scmi_handle_sys_power_state_set(msg);
            return;
        } else if (message_type == SCMI_MESSAGE_TYPE_NOTIFICATION &&
                   message_id == SCMI_MESSAGE_ID_SYS_POWER_STATE_NOTIFIER) {
            scmi_handle_sys_power_state_notifier(msg);
            return;
        }
    }

    /* Any command that is sent with an unknown protocol_id or message_id must
     * be responded to with a return value of NOT_SUPPORTED as the status code.
     */
    scmi_response_status(msg, SCMI_STATUS_NOT_SUPPORTED);
}

/**
 * \brief Handle a received SCMI response.
 *
 * \param[in] msg  SCMI message
 *
 * \return SCMI status of the response.
 */
static int32_t scmi_handle_response(const struct scmi_message_t *msg)
{
    /* Only simple status responses are currently supported */
    if (msg->payload_len != sizeof(int32_t)) {
        return SCMI_STATUS_PROTOCOL_ERROR;
    }
    return (int32_t)msg->payload[0];
}

/**
 * \brief Subscribe to system power state notifications.
 *
 * \param[in,out] msg  SCMI message
 *
 * \return Error value as defined by scmi_comms_err_t.
 */
static scmi_comms_err_t scmi_comms_notification_subscribe(struct scmi_message_t *msg)
{
    scmi_comms_err_t err;

    scmi_message_sys_power_state_notify(msg);

    err = transport_send(msg);
    if (err != SCMI_COMMS_SUCCESS) {
        return err;
    }

    err = transport_receive(msg);
    if (err != SCMI_COMMS_SUCCESS) {
        return err;
    }

    return (scmi_handle_response(msg) == SCMI_STATUS_SUCCESS) ?
           SCMI_COMMS_SUCCESS : SCMI_COMMS_GENERIC_ERROR;
}

void scmi_comms_main(void)
{
    scmi_comms_err_t err;
    struct scmi_message_t agent_buf;

    err = transport_init();
    if (err != SCMI_COMMS_SUCCESS) {
        psa_panic();
    }

    psa_irq_enable(SCP_DOORBELL_SIGNAL);

    /* First wait for SCP to signal that it is ready to receive commands. */
    (void)psa_wait(SCP_DOORBELL_SIGNAL, PSA_BLOCK);

    err = scmi_hal_doorbell_clear();
    if (err != SCMI_COMMS_SUCCESS) {
        psa_panic();
    }

    psa_eoi(SCP_DOORBELL_SIGNAL);

    /* Subscribe to notifications. If it fails, the agent will still listen for
     * SCMI commands.
     */
    err = scmi_comms_notification_subscribe(&agent_buf);
    if (err == SCMI_COMMS_SUCCESS) {
        LOG_INFFMT("SCMI Comms subscribed to power state notifications\r\n");
    } else {
        LOG_ERRFMT("SCMI Comms failed to subscribe to power state notifications\r\n");
    }

    while (1) {
        (void)psa_wait(SCP_DOORBELL_SIGNAL, PSA_BLOCK);

        err = transport_receive(&agent_buf);
        if (err == SCMI_COMMS_SUCCESS) {
            scmi_handle_message(&agent_buf);
        } else {
            scmi_response_status(&agent_buf, SCMI_STATUS_PROTOCOL_ERROR);
        }
        transport_respond(&agent_buf);

        psa_eoi(SCP_DOORBELL_SIGNAL);
    }
}
