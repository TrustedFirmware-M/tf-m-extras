/*
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <argp.h>
#include <stdio.h>
#include <stdlib.h>

#include "dice_protection_environment.h"
#include "tfm_log_unpriv.h"

#include "extra_s_tests.h"
#include "test_framework.h"

#include "cmd.h"

static struct test_suite_t test_suites[] = {
    {&register_testsuite_extra_s_interface, 0, 0, 0},
    /* End of test suites */
    {0, 0, 0, 0}
};

static char doc[] = "\nDICE Protection Environment (DPE): \n" \
                    "  - Without any argument it executes the regression test suite\n" \
                    "  - With 2 arguments it executes a DPE command as below";
static char args_doc[] = "<ARG1> <ARG2>";
static struct argp_option options[] = {
    { "cbor",           'c', "CBOR_INPUT", 0, "Execute an already CBOR encoded command."},
    { "derive-context", 'd', "RAW_INPUT",  0, "Execute a DeriveContext command."},
    { "certify-key",    'k', "RAW_INPUT",  0, "Execute a CertifyKey command."},
    { "get-cert-chain", 'g', "RAW_INPUT",  0, "Execute a GetCertificateChain command."},
    { "rnd-dpe-cmd",    'r', "RAW_INPUT",  0, "Execute a random supported command."},
    { 0 }
};

struct arguments {
    enum cmd cmd;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;

    switch (key) {
    case 'c': arguments->cmd = CBOR; break;
    case 'd': arguments->cmd = DC; break;
    case 'k': arguments->cmd = CK; break;
    case 'g': arguments->cmd = GCC; break;
    case 'r': arguments->cmd = RND; break;
    case ARGP_KEY_ARG:
        argp_usage(state);
        break;
    default: return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static int read_cmd(const char path[], char *cmd_buf, size_t *cmd_buf_size)
{
    FILE *fd;
    size_t cmd_size;

    if ((fd = fopen(path, "r")) == NULL) {
        printf("ERROR: File (%s) cannot be opened.\n", path);
        return -1;
    }

    fseek(fd, 0, SEEK_END);
    cmd_size = ftell(fd);
    rewind(fd);

    if (*cmd_buf_size < cmd_size) {
        printf("ERROR: cmd_buf is too small\n");
        return -1;
    }

    for (size_t i = 0; i < cmd_size; ++i) {
        cmd_buf[i] = fgetc(fd);
    }
    *cmd_buf_size = cmd_size;

    fclose(fd);

    return 0;
}

int main(int argc, char **argv)
{
    int context_handle;
    int ret;
    char cmd_in_buf[4096] = {0};
    size_t cmd_in_size = sizeof(cmd_in_buf);
    dpe_error_t err;
    struct arguments arguments;
    struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0 };

    dpe_lib_init(&context_handle);
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    if (argc == 1) {
       /*************** Invoked without any command line parameter ************/
        printf("Execute DPE regression test\n");
        /* Regression test prints the result to the console */
        (void)run_test("DPE Regression", test_suites);

    } else if (argc == 3) {
        /****************** Input params are provided *************************/
        INFO_UNPRIV_RAW("Execute DPE API test (%s %s)\n", argv[1], argv[2]);
        ret = read_cmd(argv[2], cmd_in_buf, &cmd_in_size);
        if (ret < 0) {
            exit(1);
        }

        err = exec_dpe_cmd(arguments.cmd, cmd_in_buf, cmd_in_size, &context_handle);
        if (err != DPE_NO_ERROR) {
            printf("DPE command decode/execution failed (%d)\n", ret);
            exit(1);
        }
    }

    exit(0);
}
