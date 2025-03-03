/*
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include "dice_protection_environment.h"
#include "dpe_client.h"
#include "dpe_context_mngr.h"
#include "dpe_cmd_decode.h"
#include "dpe_cmd_encode.h"

#include "cmd.h"
#include "root_keys.h"

#include "test_framework.h"

#include "dpe_test.h"
#include "dpe_test_common.h"
#include "dpe_test_data.h"
#include "dpe_test_private.h"

#include "tfm_log_unpriv.h"

#define CLIENT_ID_NS -1

extern int retained_rot_ctx_handle;

extern const struct dpe_test_data_t test_data[5];

static const DiceInputValues dice_in = DEFAULT_DICE_INPUT;

static const unsigned int cert_id_arr[4] = {
    DPE_CERT_ID_INVALID, 1, 2, DPE_CERT_ID_SAME_AS_PARENT
};

/* Data for key derivation */
static const char label[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
};

/*
 * Valid COSE_Key from RFC8152:
 *   https://datatracker.ietf.org/doc/html/rfc8152#appendix-C.7.1
 */
static const char ext_pub_key[] = {
    0xA5, 0x20, 0x01, 0x21, 0x58, 0x20, 0x65, 0xED, 0xA5, 0xA1, 0x25, 0x77, 0xC2, 0xBA, 0xE8,
    0x29, 0x43, 0x7F, 0xE3, 0x38, 0x70, 0x1A, 0x10, 0xAA, 0xA3, 0x75, 0xE1, 0xBB, 0x5B, 0x5D,
    0xE1, 0x08, 0xDE, 0x43, 0x9C, 0x08, 0x55, 0x1D, 0x22, 0x58, 0x20, 0x1E, 0x52, 0xED, 0x75,
    0x70, 0x11, 0x63, 0xF7, 0xF9, 0xE4, 0x0D, 0xDF, 0x9F, 0x34, 0x1B, 0x3D, 0xC9, 0xBA, 0x86,
    0x0A, 0xF7, 0xE0, 0xCA, 0x7C, 0xA7, 0xE9, 0xEE, 0xCD, 0x00, 0x84, 0xD1, 0x9C, 0x01, 0x02,
    0x02, 0x58, 0x24, 0x6D, 0x65, 0x72, 0x69, 0x61, 0x64, 0x6F, 0x63, 0x2E, 0x62, 0x72, 0x61,
    0x6E, 0x64, 0x79, 0x62, 0x75, 0x63, 0x6B, 0x40, 0x62, 0x75, 0x63, 0x6B, 0x6C, 0x61, 0x6E,
    0x64, 0x2E, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,
};

struct dc_fuzz_input_raw {
    unsigned char test_data_id;
    unsigned char cert_id;
    unsigned char retain_parent_context;
    unsigned char allow_new_context_to_derive;
    unsigned char create_certificate;
    unsigned char return_certificate;
    unsigned char allow_new_context_to_export;
    unsigned char export_cdi;
};

struct ck_fuzz_input_raw {
    unsigned char test_data_id;
    unsigned char retain_context;
    unsigned char use_external_key;
    unsigned char label_size;
};

struct gcc_fuzz_input_raw {
    unsigned char test_data_id;
    unsigned char retain_context;
    unsigned char clear_from_context;
};

struct gcc_fuzz_input {
    unsigned char test_data_id;
    bool retain_context;
    bool clear_from_context;
};

union dpe_cmd {
    struct dc_fuzz_input_raw   dc_raw;
    struct ck_fuzz_input_raw   ck_raw;
    struct gcc_fuzz_input_raw gcc_raw;
};

struct rnd_cmd_fuzz_input_raw {
    unsigned char cmd_id;
    union dpe_cmd cmd;
};

static void print_buf(const unsigned char *buf, size_t size)
{
    size_t i;

    if (buf != NULL) {
        for (i = 0; i < size; ++i) {
            if ((i & 0xF) == 0) {
                VERBOSE_UNPRIV_RAW("\n");
            }
            if (buf[i] < 0x10) {
                VERBOSE_UNPRIV_RAW(" 0%x", buf[i]);
            } else {
                VERBOSE_UNPRIV_RAW(" %x", buf[i]);
            }
        }
    }
    VERBOSE_UNPRIV_RAW("\n");
    VERBOSE_UNPRIV_RAW("\n");
}

static void build_internal_state(int *context_handle, unsigned char test_data_id)
{
    struct test_result_t test_ret = {0};
    int err;

    VERBOSE_UNPRIV_RAW("\nDeriving RoT context:\n");
    derive_rot_certificate_context(&test_ret);
    if (test_ret.val != TEST_PASSED) {
        printf("ERROR: RoT context derivation failed\n");
        exit(1);
    }

    if (test_data_id < ARRAY_SIZE(test_data)) {
        VERBOSE_UNPRIV_RAW("\nBuilding internal state: test_data[%d]\n", test_data_id);
        err = build_certificate_chain(&test_data[test_data_id]);
        if (err) {
            printf("\nERROR: Building certificate chain based on test data failed: %d\n", err);
            exit(1);
        }
        VERBOSE_UNPRIV_RAW("Building internal state: Done\n\n");
        *context_handle = get_last_context_handle(&test_data[test_data_id]);
    } else {
        VERBOSE_UNPRIV_RAW("Building internal state: No\n\n");
        *context_handle = retained_rot_ctx_handle;
    }
}

static void
map_rnd_cmd_input(enum cmd *cmd, const char *cmd_in_buf, size_t cmd_in_size)
{
    struct rnd_cmd_fuzz_input_raw *rnd_cmd_raw;

    /* If input is longer than just truncate it */
    rnd_cmd_raw = (struct rnd_cmd_fuzz_input_raw *)cmd_in_buf;

    *cmd = rnd_cmd_raw->cmd_id % MAX_CMD_VAL;
}

static dpe_error_t
rnd_cmd(const char *cmd_in_buf, size_t cmd_in_size, int *context_handle)
{
    enum cmd cmd;

    map_rnd_cmd_input(&cmd, cmd_in_buf, cmd_in_size);

    /* The internal state based on test_data[] will be built by the invoked
     * commnad later.
     */

    /* The first byte was consumed, it determines the DPE command type */
    return exec_dpe_cmd(cmd, cmd_in_buf + 1, cmd_in_size - 1, context_handle);
}

/* Set a valid handle in the CBOR encoded commands */
//static void update_context_handle(const char *buf, size_t len, int ctx_handle)
//{
////TODO: If internal state is built up before command execution, then the
////      hard-coded context_handle must be updated to a valid one.
//}

static dpe_error_t
cbor_cmd(const char *cmd_in_buf, size_t cmd_in_size, int *context_handle)
{
    char cmd_out_buf[2 * 4096];
    size_t cmd_out_size = sizeof(cmd_out_buf);
    dpe_error_t err;

   //TODO: Might test with pre-built internal state
   //build_internal_state(context_handle, 0);
   //update_context_handle(cmd_in_buf, cmd_in_size, context_handle);

    (void)context_handle;

    VERBOSE_UNPRIV_RAW("DPE request (%ld):\n", cmd_in_size);
    print_buf(cmd_in_buf, cmd_in_size);

    err = dpe_command_decode(CLIENT_ID_NS,
                             cmd_in_buf, cmd_in_size,
                             cmd_out_buf, &cmd_out_size);

    VERBOSE_UNPRIV_RAW("DPE response (%ld):\n", cmd_out_size);
    print_buf(cmd_out_buf, cmd_out_size);

    return err;
}

static bool map_to_bool(unsigned char val)
{
    return (val % 2) ? true : false;
}

/*
 * Restrict the inputs:
 *  - cert_id: Only allow 4 different valid values
 *  - bools: Ensure that true and false values appears equally frequent
 */
static void
map_dc_input(struct derive_context_cmd_input_t *dc, unsigned char *test_data_id,
             const char *cmd_in_buf, size_t cmd_in_size)
{
    struct dc_fuzz_input_raw *dc_raw;

    /* If the input is longer than just truncate it */
    dc_raw = (struct dc_fuzz_input_raw *)cmd_in_buf;

    dc->cert_id = cert_id_arr[(dc_raw->cert_id % ARRAY_SIZE(cert_id_arr))];
    dc->retain_parent_context = map_to_bool(dc_raw->retain_parent_context);
    dc->allow_new_context_to_derive = map_to_bool(dc_raw->allow_new_context_to_derive);
    dc->create_certificate = map_to_bool(dc_raw->create_certificate);
    dc->return_certificate = map_to_bool(dc_raw->return_certificate);
    dc->allow_new_context_to_export = map_to_bool(dc_raw->allow_new_context_to_export);
    dc->export_cdi = map_to_bool(dc_raw->export_cdi);

    *test_data_id = dc_raw->test_data_id;
}

static dpe_error_t
dc_cmd(const char *cmd_in_buf, size_t cmd_in_size, int *context_handle)
{
    struct derive_context_cmd_input_t dc_input = DEFAULT_DC_CMD_INPUT;
    struct derive_context_cmd_output_t dc_output = {0};
    dpe_error_t err;
    unsigned char test_data_id;

    ADD_CERT_BUF(dc_output, DICE_CERT_SIZE);
    ADD_EXPORT_CDI_BUF(dc_output, DICE_MAX_ENCODED_CDI_SIZE);

    map_dc_input(&dc_input, &test_data_id, cmd_in_buf, cmd_in_size);

    build_internal_state(context_handle, test_data_id);

    /* Set the next valid context_handle */
    dc_input.context_handle = *context_handle;

    err = CALL_DERIVE_CONTEXT(dc_input, dc_output);

    if (dc_output.certificate_actual_size > 0) {
            VERBOSE_UNPRIV_RAW("Certificate:\n");
            print_buf(dc_output.certificate_buf,
                      dc_output.certificate_actual_size);
    }

    if (dc_output.exported_cdi_actual_size > 0) {
            VERBOSE_UNPRIV_RAW("CDIs:\n");
            print_buf(dc_output.exported_cdi_buf,
                      dc_output.exported_cdi_actual_size);
    }

    return err;
}

static void
map_ck_input(struct certify_key_cmd_input_t *ck,  unsigned char *test_data_id,
             const char *cmd_in_buf, size_t cmd_in_size)
{
    struct ck_fuzz_input_raw *ck_raw;

    /* If the input is longer than just truncate it */
    ck_raw = (struct ck_fuzz_input_raw *)cmd_in_buf;

    ck->retain_context = map_to_bool(ck_raw->retain_context);

    if (map_to_bool(ck_raw->use_external_key)) {
        ck->public_key = ext_pub_key;
        ck->public_key_size = sizeof(ext_pub_key);
    }

    ck->label_size = (size_t)ck_raw->label_size;
}

static dpe_error_t
ck_cmd(const char *cmd_in_buf, size_t cmd_in_size, int *context_handle)
{
    struct certify_key_cmd_input_t ck_input = DEFAULT_CK_CMD_INPUT;
    struct certify_key_cmd_output_t ck_output = {0};
    dpe_error_t err;
    unsigned char test_data_id;

    ADD_CERT_CHAIN_BUF(ck_output, 1650);
    ADD_DERIVED_PUB_KEY_BUF(ck_output, DPE_ATTEST_PUB_KEY_SIZE);

    map_ck_input(&ck_input, &test_data_id, cmd_in_buf, cmd_in_size);

    build_internal_state(context_handle, test_data_id);

    /* Set the next valid context_handle */
    ck_input.context_handle = *context_handle;

    err = CALL_CERTIFY_KEY(ck_input, ck_output);

    if (ck_output.certificate_chain_actual_size > 0) {
            VERBOSE_UNPRIV_RAW("Certificate:\n");
            print_buf(ck_output.certificate_chain_buf,
                      ck_output.certificate_chain_actual_size);
    }

    if (ck_output.derived_public_key_actual_size > 0) {
            VERBOSE_UNPRIV_RAW("Public key:\n");
            print_buf(ck_output.derived_public_key_buf,
                      ck_output.derived_public_key_actual_size);
    }

    return err;
}

static void
map_gcc_input(struct gcc_fuzz_input *gcc, unsigned char *test_data_id,
              const char *cmd_in_buf, size_t cmd_in_size)
{
    struct gcc_fuzz_input_raw *gcc_raw;

    /* If the input is longer than just truncate it */
    gcc_raw = (struct gcc_fuzz_input_raw *)cmd_in_buf;

    gcc->retain_context = map_to_bool(gcc_raw->retain_context);
    gcc->clear_from_context = map_to_bool(gcc_raw->clear_from_context);
}

static dpe_error_t
gcc_cmd(const char *cmd_in_buf, size_t cmd_in_size, int *context_handle)
{
    int new_context_handle;
    struct gcc_fuzz_input gcc;
    char cert_buf[4096];
    size_t cert_size = 0;
    dpe_error_t err;
    unsigned char test_data_id;

    map_gcc_input(&gcc, &test_data_id, cmd_in_buf, cmd_in_size);

    build_internal_state(context_handle, test_data_id);

    err = dpe_get_certificate_chain(*context_handle,
                                    gcc.retain_context,
                                    gcc.clear_from_context,
                                    cert_buf,
                                    sizeof(cert_buf),
                                    &cert_size,
                                    &new_context_handle);

    if (cert_size > 0) {
            VERBOSE_UNPRIV_RAW("Certificate:\n");
            print_buf(cert_buf, cert_size);
    }

    return err;
}

/*
 * DPE Library Init:
 * - crypto_lib
 * - platform
 * - context manager
 */
void dpe_lib_init(int *context_handle)
{
    int ret;
    dpe_error_t err;

    ret = psa_crypto_init();
    if (ret != 0) {
        printf("ERROR: Crypto init failed! (%d)\n", ret);
        exit(1);
    }

    ret = register_rot_cdi();
    if (ret != 0) {
        printf("ERROR: RoT CDI registration failed! (%d)\n", ret);
        exit(1);
    }

    ret = register_root_attest_key();
    if (ret != 0) {
        printf("ERROR: Root attest key registration failed! (%d)\n", ret);
        exit(1);
    }

    err = initialise_context_mngr(context_handle);
    if (err != DPE_NO_ERROR) {
        printf("ERROR: Context manager init failed (%d)\n", err);
        exit(1);
    }
}

dpe_error_t exec_dpe_cmd(enum cmd cmd, const char *cmd_in_buf,
                         size_t cmd_in_size, int *context_handle)
{
    switch(cmd) {
    case CBOR:
        return cbor_cmd(cmd_in_buf, cmd_in_size, context_handle);
    case DC:
        return dc_cmd(cmd_in_buf, cmd_in_size, context_handle);
    case CK:
        return ck_cmd(cmd_in_buf, cmd_in_size, context_handle);
    case GCC:
        return gcc_cmd(cmd_in_buf, cmd_in_size, context_handle);
    case RND:
        return rnd_cmd(cmd_in_buf, cmd_in_size, context_handle);
    default:
        printf("ERROR: Unknown command\n");
        exit(1);
    }
}
