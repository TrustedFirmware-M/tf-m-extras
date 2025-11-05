/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 */

#include "psa/service.h"
#include "psa_manifest/scmi_comms.h"
#include "scmi_comms.h"
#include "scmi_hal.h"
#include "tfm_log_unpriv.h"

/* From TF-M common */
#include "scmi_common.h"
#include "scmi_system_power.h"
#include "scmi_protocol.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

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

/** SCMI shareed memory direction A<->P */
/*
 * This partition acts as an SCMI Agent, thus:
 * A2P: Commands sent to the platform, which implements "all" the protocols
 * P2A: Notifications received by the platform, occasionally may receive
 *      commands from the platform.
 */
enum scmi_entity_direction_t {
    /** SCMI direction invalid */
    SCMI_ENTITY_DIRECTION_UNKNOWN = 0,
    /** SCMI direction sender (A->P), acts as an agent */
    SCMI_ENTITY_DIRECTION_SENDER = 1,
    /** SCMI direction receiver (P->A), acts as a platform/client */
    SCMI_ENTITY_DIRECTION_RECEIVER = 2,

    _SCMI_ENTITY_DIRECTION_PAD = UINT32_MAX
};

/* Sender shared memory: Agent -> Platform */
static struct transport_buffer_t *const shared_memory_a2p =
    (struct transport_buffer_t *)SCP_SHARED_MEMORY_BASE;

/* Receiver shared memory: Platform -> Agent */
static struct transport_buffer_t *const shared_memory_p2a =
    (struct transport_buffer_t *)SCP_SHARED_MEMORY_RECEIVER_BASE;

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

    shared_memory_a2p->flags = 0;
    shared_memory_a2p->length = 0;
    shared_memory_a2p->status = TRANSPORT_BUFFER_STATUS_FREE_MASK;

    shared_memory_p2a->flags = 0;
    shared_memory_p2a->length = 0;
    shared_memory_p2a->status = TRANSPORT_BUFFER_STATUS_FREE_MASK;

    return SCMI_COMMS_SUCCESS;
}

/**
 * \brief Read a message from the shared memory to the local buffer.
 *
 * \param[out] msg  SCMI message
 * \param[in]  dir  Direction of the message
 *
 * \return Error value as defined by scmi_comms_err_t.
 */
static scmi_comms_err_t transport_receive(
    struct scmi_message_t *msg,
    enum scmi_entity_direction_t dir)
{
    struct transport_buffer_t *sh_mem;
    scmi_comms_err_t err;
    uint32_t msg_length;

    err = scmi_hal_doorbell_clear();
    if (err != SCMI_COMMS_SUCCESS) {
        return err;
    }

    switch (dir) {
    case SCMI_ENTITY_DIRECTION_SENDER:
        sh_mem = shared_memory_a2p;
        break;

    case SCMI_ENTITY_DIRECTION_RECEIVER:
        sh_mem = shared_memory_p2a;
        break;

    default:
        return SCMI_COMMS_GENERIC_ERROR;
    }

    msg_length = sh_mem->length;

    if ((msg_length < sizeof(sh_mem->message_header)) ||
        (msg_length > TRANSPORT_BUFFER_MAX_LENGTH)) {
        return SCMI_COMMS_INVALID_ARGUMENT;
    }

    memcpy(msg, &sh_mem->message_header, msg_length);
    msg->payload_len = msg_length - sizeof(msg->header);

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
    /*
     * SENDER - A2P response:
     * Process command (done)
     * Populate payload
     * Mark channel as free
     */
    /* Populate shared memory area */
    memcpy(shared_memory_p2a->message_payload, msg->payload, msg->payload_len);
    shared_memory_p2a->length = msg->payload_len + sizeof(msg->header);
}

/**
 * \brief Complete the response to the shared memory and signal completion.
 */
static void transport_complete(void)
{
    /* Mark channel as free */
    shared_memory_p2a->status |= TRANSPORT_BUFFER_STATUS_FREE_MASK;

#ifdef TRANSPORT_COMPLETION_INTERRUPT_SUPPORTED
    /* TODO: Issue completion interrupt */
#endif
}

/**
 * \brief Write a message from the local buffer to the shared memory and wait
 *        for a response.
 *
 * \param[in] msg  SCMI message
 *
 * \return Error value as defined by scmi_comms_err_t.
 */
static scmi_comms_err_t transport_send(const struct scmi_message_t *msg)
{
    scmi_comms_err_t err;
    uint32_t length = msg->payload_len + sizeof(msg->header);

    if (length > TRANSPORT_BUFFER_MAX_LENGTH) {
        return SCMI_COMMS_INVALID_ARGUMENT;
    }

    /* Wait for channel to be free */
    /* TODO: Timeout */
    while (!(shared_memory_a2p->status & TRANSPORT_BUFFER_STATUS_FREE_MASK));

    /* Populate shared memory area */
    memcpy(&shared_memory_a2p->message_header, msg, length);
    shared_memory_a2p->length = length;

#ifdef TRANSPORT_COMPLETION_INTERRUPT_SUPPORTED
    /* Interrupt-driven communications flow */
    shared_memory_a2p->flags |= TRANSPORT_BUFFER_FLAGS_INTERRUPT_MASK;
#endif

    /* Mark channel as busy */
    shared_memory_a2p->status &= ~TRANSPORT_BUFFER_STATUS_FREE_MASK;

    /* Ring doorbell */
    err = scmi_hal_doorbell_ring();
    if (err != SCMI_COMMS_SUCCESS) {
        return err;
    }

#ifdef TRANSPORT_COMPLETION_INTERRUPT_SUPPORTED
    /* TODO: Wait for completion interrupt */
#else
    /* Wait until channel is free */
    while (!(shared_memory_a2p->status & TRANSPORT_BUFFER_STATUS_FREE_MASK));
#endif

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
        /*
         * Invalid notification message received.
         * No return values for notifications.
         */
        msg->payload_len = 0;
        return;
    }

    struct scmi_sys_power_state_notifier_t *sys_pwr_notif =
        (struct scmi_sys_power_state_notifier_t *)msg->payload;

    scmi_hal_sys_power_state(
        sys_pwr_notif->agent_id,
        sys_pwr_notif->flags,
        sys_pwr_notif->system_state);
}

/**
 * \brief Handle a received SCMI message.
 *
 * \param[in,out] msg  SCMI message
 */
static bool scmi_handle_message_and_respond(struct scmi_message_t *msg)
{
    uint8_t message_id = (msg->header & SCMI_MESSAGE_HEADER_MESSAGE_ID_MASK)
                         >> SCMI_MESSAGE_HEADER_MESSAGE_ID_POS;
    uint8_t message_type = (msg->header & SCMI_MESSAGE_HEADER_MESSAGE_TYPE_MASK)
                           >> SCMI_MESSAGE_HEADER_MESSAGE_TYPE_POS;
    uint8_t protocol_id = (msg->header & SCMI_MESSAGE_HEADER_PROTOCOL_ID_MASK)
                          >> SCMI_MESSAGE_HEADER_PROTOCOL_ID_POS;

    bool require_response = true;

    if (protocol_id == SCMI_PROTOCOL_ID_SYS_POWER_STATE) {
        if ((message_type == SCMI_MESSAGE_TYPE_COMMAND) &&
            (message_id == SCMI_MESSAGE_ID_SYS_POWER_STATE_SET)) {
            scmi_handle_sys_power_state_set(msg);

            return require_response;
        } else if (message_type == SCMI_MESSAGE_TYPE_NOTIFICATION) {
            /* Received notifications do not require a response */
            require_response = false;

            if (message_id == SCMI_MESSAGE_ID_SYS_POWER_STATE_NOTIFIER) {
                scmi_handle_sys_power_state_notifier(msg);
            }

            return require_response;
        }
    }

    /* Any command that is sent with an unknown protocol_id or message_id must
     * be responded to with a return value of NOT_SUPPORTED as the status code.
     */
    scmi_response_status(msg, SCMI_STATUS_NOT_SUPPORTED);
    return require_response;
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

    err = transport_receive(msg, SCMI_ENTITY_DIRECTION_SENDER);
    if (err != SCMI_COMMS_SUCCESS) {
        return err;
    }

    return (scmi_handle_response(msg) == SCMI_STATUS_SUCCESS) ?
           SCMI_COMMS_SUCCESS : SCMI_COMMS_GENERIC_ERROR;
}

/**
 * \brief Subscribe to system power state notifications, by sending the message,
 *      wait and reply.
 *
 * \param[in,out] msg  SCMI message
 *
 * \return Error value as defined by scmi_comms_err_t.
 */
static scmi_comms_err_t scmi_comms_notification_subscribe_and_wait(
    struct scmi_message_t *msg)
{
    scmi_comms_err_t err;

    scmi_message_sys_power_state_notify(msg);

    err = transport_send(msg);
    if (err != SCMI_COMMS_SUCCESS) {
        return err;
    }

    (void)psa_wait(SCP_DOORBELL_SIGNAL, PSA_BLOCK);

    err = transport_receive(msg, SCMI_ENTITY_DIRECTION_SENDER);
    if (err != SCMI_COMMS_SUCCESS) {
        return err;
    }

    psa_eoi(SCP_DOORBELL_SIGNAL);

    return (scmi_handle_response(msg) == SCMI_STATUS_SUCCESS) ?
           SCMI_COMMS_SUCCESS : SCMI_COMMS_GENERIC_ERROR;
}

void scmi_comms_main(void)
{
    scmi_comms_err_t err;
    struct scmi_message_t agent_buf;
    scmi_init_sequence_flags_t init_flags;
    bool hook_done;
    bool resp;

    err = transport_init();
    if (err != SCMI_COMMS_SUCCESS) {
        psa_panic();
    }

    err = scmi_hal_init_sequence_flags(&init_flags);
    if (err != SCMI_COMMS_SUCCESS) {
        psa_panic();
    }

    if ((init_flags & SCMI_INIT_SEQ_FLAG_IRQ_EN) > 0) {
        psa_irq_enable(SCP_DOORBELL_SIGNAL);
    }

    do {
        err = scmi_hal_init_sequence_hook(&hook_done);
        if (err != SCMI_COMMS_SUCCESS) {
            psa_panic();
        }

        if (hook_done) {
            break;
        }

        if ((init_flags & SCMI_INIT_SEQ_FLAG_IRQ_WAIT) > 0) {
            (void)psa_wait(SCP_DOORBELL_SIGNAL, PSA_BLOCK);
        }
    } while (!hook_done);

    if ((init_flags & SCMI_INIT_SEQ_FLAG_IRQ_WAIT) > 0) {
        psa_eoi(SCP_DOORBELL_SIGNAL);
    }

    /* Subscribe to notifications. If it fails, the agent will still listen for
     * SCMI commands.
     */

    if ((init_flags & SCMI_INIT_SEQ_FLAG_SUBSCRIBE_WAIT) > 0) {
        err = scmi_comms_notification_subscribe_and_wait(&agent_buf);
    } else {
        err = scmi_comms_notification_subscribe(&agent_buf);
    }
    if (err == SCMI_COMMS_SUCCESS) {
        INFO_UNPRIV_RAW("SCMI Comms subscribed to power state notifications\n");
    } else {
        ERROR_UNPRIV_RAW("SCMI Comms failed to subscribe to power state notifications\n");
    }

    while (1) {
        (void)psa_wait(SCP_DOORBELL_SIGNAL, PSA_BLOCK);

        err = transport_receive(&agent_buf, SCMI_ENTITY_DIRECTION_RECEIVER);
        if (err == SCMI_COMMS_SUCCESS) {
            resp = scmi_handle_message_and_respond(&agent_buf);
        } else {
            scmi_response_status(&agent_buf, SCMI_STATUS_PROTOCOL_ERROR);
            resp = true;
        }

        if (resp) {
            transport_respond(&agent_buf);
        }

        transport_complete();

        psa_eoi(SCP_DOORBELL_SIGNAL);
    }
}
