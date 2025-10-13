/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 */

#include "test_framework.h"
#include "scmi_hal_defs.h"
#include "tfm_hal_device_header.h"
#include "tfm_plat_test.h"
#include "scmi_protocol.h"
#include "scmi_system_power.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Duplicates of definitions in SCMI partition */
#define TRANSPORT_BUFFER_STATUS_FREE_POS  0
#define TRANSPORT_BUFFER_STATUS_FREE_MASK \
    (UINT32_C(0x1) << TRANSPORT_BUFFER_STATUS_FREE_POS)

#define TRANSPORT_BUFFER_STATUS_ERROR_POS 1
#define TRANSPORT_BUFFER_STATUS_ERROR_MASK \
    (UINT32_C(0x1) << TRANSPORT_BUFFER_STATUS_ERROR_POS)

#define TRANSPORT_BUFFER_FLAGS_INTERRUPT_POS 0
#define TRANSPORT_BUFFER_FLAGS_INTERRUPT_MASK \
    (UINT32_C(0x1) << TRANSPORT_BUFFER_FLAGS_INTERRUPT_POS)

struct transport_buffer_t {
    uint32_t reserved0; /**< Reserved, must be zero */
    volatile uint32_t status; /**< Channel status */
    uint64_t reserved1; /**< Implementation defined field */
    uint32_t flags; /**< Channel flags */
    volatile uint32_t length; /**< Length in bytes of the message header and payload */
    uint32_t message_header; /**< Message header */
    uint32_t message_payload[]; /**< Message payload */
};

static struct transport_buffer_t *const shared_memory =
    (struct transport_buffer_t *)SCP_SHARED_MEMORY_BASE;

/**
 * \brief Raise the SCMI partition's receiver doorbell and use the timer
 *        interrupt to trigger the partition's IRQ handler. Wait until the SCMI
 *        partition has cleared the doorbell.
 */
static void raise_partition_receiver_doorbell(void)
{
    /* Set the partition's receiver doorbell */
    test_doorbell_receiver = true;

    /* Start the timer to trigger the partition's interrupt */
    tfm_plat_test_secure_timer_start();

    /* Wait until the partition clears the doorbell */
    while (test_doorbell_receiver) {
        __WFE();
    }
}

/**
 * \brief Wait for the SCMI partition to raise its sender doorbell and then
 *        clear it.
 */
static void wait_for_partition_sender_doorbell(void)
{
    /* Wait for the partition to raise its sender doorbell */
    while (!test_doorbell_sender) {
        __WFE();
    }

    /* Reset the partition's sender doorbell */
    test_doorbell_sender = false;
}

/**
 * \brief Checks that the SCMI partition sends a System Power State Notify
 *        message on initialization to subscribe to system power state
 *        notifications.
 */
static void scmi_test_subscribe(struct test_result_t *ret)
{
    const uint32_t expected_payload[] = { 1 /* notify_enable */ };
    const struct transport_buffer_t expected_transport = {
        .reserved0 = 0,
        .status = 0,
        .reserved1 = 0,
        .flags = 0,
        .length = 4 + sizeof(expected_payload),
        .message_header = (SCMI_PROTOCOL_ID_SYS_POWER_STATE << 10) /* protocol_id=system_power */ |
                          (SCMI_MESSAGE_TYPE_COMMAND << 8) /* message_type=command */ |
                          SCMI_MESSAGE_ID_SYS_POWER_STATE_NOTIFY /* message_id=system_power_state_notify */,
    };

    /* First raise the partition's doorbell to signal SCP ready */
    raise_partition_receiver_doorbell();

    /* Wait for the partition to send SCMI notify subscription command */
    wait_for_partition_sender_doorbell();

    /* Check the transport buffer up to the message payload */
    if (memcmp(shared_memory, &expected_transport,
        offsetof(struct transport_buffer_t, message_payload)) != 0) {
        TEST_FAIL("Transport buffer contained unexpected values\r\n");
        return;
    }

    /* Check the message payload */
    if (memcmp(&shared_memory->message_payload, expected_payload,
        sizeof(expected_payload)) != 0) {
        TEST_FAIL("Message payload contained unexpected values\r\n");
        return;
    }

    /* Write a success response */
    shared_memory->length = 4 + 4;
    shared_memory->message_payload[0] = 0; /* SCMI_SUCCESS */
    shared_memory->status |= TRANSPORT_BUFFER_STATUS_FREE_MASK;

    /* Raise the partition's doorbell again to allow its execution to continue
     * (only required because testing is done locally).
     */
    raise_partition_receiver_doorbell();

    ret->val = TEST_PASSED;
}

/**
 * \brief Tests sending a valid notification to the SCMI partition.
 */
static void scmi_test_valid_notification(struct test_result_t *ret)
{
    const uint32_t message_header = (SCMI_PROTOCOL_ID_SYS_POWER_STATE << 10) /* protocol_id=system_power */ |
                                    (SCMI_MESSAGE_TYPE_NOTIFICATION << 8) |
                                    SCMI_MESSAGE_ID_SYS_POWER_STATE_NOTIFIER;
    const uint32_t notification_payload[] = { 0x1234 /* agent_id */,
                                              0x0 /* flags */,
                                              SCMI_SYS_POWER_STATE_SHUTDOWN};
    const struct transport_buffer_t expected_transport = {
        .reserved0 = 0,
        .status = TRANSPORT_BUFFER_STATUS_FREE_MASK,
        .reserved1 = 0,
        .flags = 0,
        .length = 16, /* there is no response */
        .message_header = message_header,
    };

    /* Write notification */
    shared_memory->length = 4 + sizeof(notification_payload);
    shared_memory->message_header = message_header;
    memcpy(shared_memory->message_payload, notification_payload,
           sizeof(notification_payload));
    shared_memory->status &= ~TRANSPORT_BUFFER_STATUS_FREE_MASK;

    /* Raise the partition's doorbell to signal message */
    raise_partition_receiver_doorbell();

    /* Check the response in the transport buffer up to the message payload */
    if (memcmp(shared_memory, &expected_transport,
        offsetof(struct transport_buffer_t, message_payload)) != 0) {
        TEST_FAIL("Transport buffer contained unexpected values\r\n");
        return;
    }

    /* No response payload for notifications */

    ret->val = TEST_PASSED;
}

/**
 * \brief Tests sending notification with invalid lengths to the SCMI partition.
 */
static void scmi_test_invalid_message_length(struct test_result_t *ret)
{
    const uint32_t message_header = (SCMI_PROTOCOL_ID_SYS_POWER_STATE << 10) /* protocol_id=system_power */ |
                                    (SCMI_MESSAGE_TYPE_NOTIFICATION << 8) |
                                    SCMI_MESSAGE_ID_SYS_POWER_STATE_NOTIFIER;
    const uint32_t notification_payload[] = { 0x1234 /* agent_id */,
                                              0x0 /* flags */,
                                              SCMI_SYS_POWER_STATE_SHUTDOWN};
    struct transport_buffer_t expected_transport = {
        .reserved0 = 0,
        .status = TRANSPORT_BUFFER_STATUS_FREE_MASK,
        .reserved1 = 0,
        .flags = 0,
        .length = 4 + 4,
        .message_header = message_header,
    };

    /*
     * TEST 1
     * Write notification with length too small for header
     */
    shared_memory->length = 3;
    shared_memory->message_header = message_header;
    memcpy(shared_memory->message_payload, notification_payload,
           sizeof(notification_payload));
    shared_memory->status &= ~TRANSPORT_BUFFER_STATUS_FREE_MASK;

    raise_partition_receiver_doorbell();

    if (memcmp(shared_memory, &expected_transport,
        offsetof(struct transport_buffer_t, message_payload)) != 0) {
        TEST_FAIL("Transport buffer contained unexpected values\r\n");
        return;
    }

    if (shared_memory->message_payload[0] != (uint32_t)SCMI_STATUS_PROTOCOL_ERROR) {
        TEST_FAIL("Invalid length did not return PROTOCOL_ERROR\r\n");
        return;
    }

    /*
     * TEST 2
     * Write notification with length that does not match message
     */
    shared_memory->length = 8;
    shared_memory->message_header = message_header;
    memcpy(shared_memory->message_payload, notification_payload,
           sizeof(notification_payload));
    shared_memory->status &= ~TRANSPORT_BUFFER_STATUS_FREE_MASK;

    raise_partition_receiver_doorbell();

    if (memcmp(shared_memory, &expected_transport,
        offsetof(struct transport_buffer_t, message_payload)) != 0) {
        TEST_FAIL("Transport buffer contained unexpected values\r\n");
        return;
    }

    /*
     * TEST 3
     * Write notification with length too large for transport
     */
    shared_memory->length = UINT32_MAX;
    shared_memory->message_header = message_header;
    memcpy(shared_memory->message_payload, notification_payload,
           sizeof(notification_payload));
    shared_memory->status &= ~TRANSPORT_BUFFER_STATUS_FREE_MASK;

    raise_partition_receiver_doorbell();

    if (memcmp(shared_memory, &expected_transport,
        offsetof(struct transport_buffer_t, message_payload)) != 0) {
        TEST_FAIL("Transport buffer contained unexpected values\r\n");
        return;
    }

    if (shared_memory->message_payload[0] != (uint32_t)SCMI_STATUS_PROTOCOL_ERROR) {
        TEST_FAIL("Invalid length did not return PROTOCOL_ERROR\r\n");
        return;
    }

    ret->val = TEST_PASSED;
}

/**
 * \brief Tests sending a message with an invalid header to the SCMI partition.
 */
static void scmi_test_invalid_message_header(struct test_result_t *ret)
{
    const uint32_t message_header = 0xDEADBEEF;
    const uint32_t message_payload[] = { 0xF00 };
    const struct transport_buffer_t expected_transport = {
        .reserved0 = 0,
        .status = 1,
        .reserved1 = 0,
        .flags = 0,
        .length = 4 + 4,
        .message_header = message_header,
    };

    /* Write message with an unknown message header */
    shared_memory->length = 4 + sizeof(message_payload);
    shared_memory->message_header = message_header;
    memcpy(shared_memory->message_payload, message_payload,
           sizeof(message_payload));
    shared_memory->status &= ~TRANSPORT_BUFFER_STATUS_FREE_MASK;

    raise_partition_receiver_doorbell();

    if (memcmp(shared_memory, &expected_transport,
        offsetof(struct transport_buffer_t, message_payload)) != 0) {
        TEST_FAIL("Transport buffer contained unexpected values\r\n");
        return;
    }

    if (shared_memory->message_payload[0] != (uint32_t)SCMI_STATUS_NOT_SUPPORTED) {
        TEST_FAIL("Invalid message type did not return NOT_SUPPORTED\r\n");
        return;
    }

    ret->val = TEST_PASSED;
}

static struct test_t scmi_s_tests[] = {
    {&scmi_test_subscribe, "SCMI_S_TEST_1001",
     "SCMI notification subscription test"},
    {&scmi_test_valid_notification, "SCMI_S_TEST_1002",
     "SCMI valid notification test"},
    {&scmi_test_invalid_message_length, "SCMI_S_TEST_1003",
     "SCMI invalid message length test"},
    {&scmi_test_invalid_message_header, "SCMI_S_TEST_1004",
     "SCMI invalid message header test"},
};

void register_testsuite_extra_s_interface(struct test_suite_t *p_test_suite)
{
    uint32_t list_size = sizeof(scmi_s_tests) / sizeof(scmi_s_tests[0]);

    set_testsuite("SCMI Secure Tests (SCMI_S_TEST_1XXX)",
                  scmi_s_tests, list_size, p_test_suite);
}
