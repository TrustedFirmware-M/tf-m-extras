/*
 * Copyright (c) 2022-2023, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef __TEST_VALUES_H__
#define __TEST_VALUES_H__

#include "measured_boot_api.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Measurement slots used for individual test */
#define TEST_1003_SLOT_INDEX NUM_OF_MEASUREMENT_SLOTS

#ifdef DOMAIN_NS
#define TEST_1001_SLOT_INDEX 10
#define TEST_1002_SLOT_INDEX 11
#define TEST_1004_SLOT_INDEX 12
#define TEST_1005_SLOT_INDEX 13
#define TEST_1006_SLOT_INDEX 14
#define TEST_1007_SLOT_INDEX 15
#define TEST_1008_SLOT_INDEX 16
#define TEST_1009_SLOT_INDEX 17
#define TEST_1010_SLOT_INDEX 18
#define TEST_1011_SLOT_INDEX 19
#define TEST_1012_SLOT_INDEX 31
#else
#define TEST_1001_SLOT_INDEX 20
#define TEST_1002_SLOT_INDEX 21
#define TEST_1004_SLOT_INDEX 22
#define TEST_1005_SLOT_INDEX 23
#define TEST_1006_SLOT_INDEX 24
#define TEST_1007_SLOT_INDEX 25
#define TEST_1008_SLOT_INDEX 26
#define TEST_1009_SLOT_INDEX 27
#define TEST_1010_SLOT_INDEX 28
#define TEST_1011_SLOT_INDEX 29
#define TEST_1012_SLOT_INDEX 30
#endif

#define TEST_1013_SLOT_INDEX TEST_1007_SLOT_INDEX
#define TEST_1014_SLOT_INDEX TEST_1007_SLOT_INDEX

#define TEST_DATA_COUNT 4

#define SIGNER_ID_TEST_0                              \
    0x01, 0x05, 0x01, 0xEF, 0x68, 0x07, 0x88, 0xCC,   \
    0x33, 0x06, 0x54, 0xAB, 0x09, 0x01, 0x74, 0x77,   \
    0x49, 0x08, 0x93, 0xA8, 0x01, 0x07, 0xEF, 0x01,   \
    0x83, 0x09, 0x22, 0xCD, 0x09, 0x61, 0xB6, 0xFF,   \
    0x01, 0x05, 0x01, 0xEF, 0x68, 0x07, 0x88, 0xCC,   \
    0x33, 0x06, 0x54, 0xAB, 0x09, 0x01, 0x74, 0x77,   \
    0x49, 0x08, 0x93, 0xA8, 0x01, 0x07, 0xEF, 0x01,   \
    0x83, 0x09, 0x22, 0xCD, 0x09, 0x61, 0xB6, 0xFF

#define TEST_VALUE_SIGNER_ID                          \
    (struct test_buf_t) {                             \
     (uint8_t[]){SIGNER_ID_TEST_0},                   \
     SIGNER_ID_MAX_SIZE                               \
    }

#define SW_VERSION_TEST_0                             \
    0x32, 0x35, 0x35, 0x2E, 0x32, 0x35, 0x35, 0x2E,   \
    0x36, 0x35, 0x35, 0x33, 0x35, 0x0

#define TEST_VALUE_SW_VERSION                         \
    (struct test_buf_t) {                             \
     (uint8_t[]){SW_VERSION_TEST_0},                  \
     VERSION_MAX_SIZE                                 \
    }

#define SW_MEASUREMENT_DESC_TEST_0                    \
    0x4D, 0x45, 0x41, 0x53, 0x55, 0x52, 0x45, 0x44,   \
    0x5F, 0x42, 0x4F, 0x4F, 0x54, 0x5F, 0x54, 0x45,   \
    0x53, 0x54, 0x53, 0x0

#define TEST_VALUE_SW_MEASUREMENT_DESC                \
    (struct test_buf_t) {                             \
     (uint8_t[]){SW_MEASUREMENT_DESC_TEST_0},         \
     SW_TYPE_MAX_SIZE                                 \
    }

#define TEST_VALUE_ZERO                               \
    (struct test_buf_t) {                             \
     (uint8_t[]){0x0},                                \
     0x0                                              \
    }

#define SHA256_SIZE 32
#define SHA512_SIZE 64

#define SW_SHA256_VAL_TEST_0                          \
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,   \
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,   \
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,   \
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb

/* Below value is calculated as follows
 * sha256 (default_slot_measurement_value || SW_SHA256_VAL_TEST_0)
 * i.e.
 * sha256(0000000000000000000000000000000000000000000000000000000000000000 ||
 *        bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)
 *      = 86bfbce7f88e77dab6bbfb923bb70e2411d374dc658db751c9bdec438f5cce54
 */
#define EXPECTED_SHA256_MEASUREMENT_VAL_TEST_0        \
    0x86, 0xbf, 0xbc, 0xe7, 0xf8, 0x8e, 0x77, 0xda,   \
    0xb6, 0xbb, 0xfb, 0x92, 0x3b, 0xb7, 0x0e, 0x24,   \
    0x11, 0xd3, 0x74, 0xdc, 0x65, 0x8d, 0xb7, 0x51,   \
    0xc9, 0xbd, 0xec, 0x43, 0x8f, 0x5c, 0xce, 0x54    \

/* Below value is calculated as follows
 * sha512 (default_slot_measurement_value || SW_SHA256_VAL_TEST_0)
 * i.e.
 * sha512(0000000000000000000000000000000000000000000000000000000000000000...
 *        0000000000000000000000000000000000000000000000000000000000000000 ||
 *        bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)
 *      = a634b5b6e5e9715d4788f72f1a39c3e2d2e103decfb8f8d622ccff8cb2e3e822...
 *        74316c4b8d662511cc1cf90a2456dff2b620d3bef0e0b956cf3acc78e658be40
 */
#define EXPECTED_SHA512_MEASUREMENT_VAL_TEST_0        \
    0xa6, 0x34, 0xb5, 0xb6, 0xe5, 0xe9, 0x71, 0x5d,   \
    0x47, 0x88, 0xf7, 0x2f, 0x1a, 0x39, 0xc3, 0xe2,   \
    0xd2, 0xe1, 0x03, 0xde, 0xcf, 0xb8, 0xf8, 0xd6,   \
    0x22, 0xcc, 0xff, 0x8c, 0xb2, 0xe3, 0xe8, 0x22,   \
    0x74, 0x31, 0x6c, 0x4b, 0x8d, 0x66, 0x25, 0x11,   \
    0xcc, 0x1c, 0xf9, 0x0a, 0x24, 0x56, 0xdf, 0xf2,   \
    0xb6, 0x20, 0xd3, 0xbe, 0xf0, 0xe0, 0xb9, 0x56,   \
    0xcf, 0x3a, 0xcc, 0x78, 0xe6, 0x58, 0xbe, 0x40

#define SW_SHA256_VAL_TEST_1                          \
    0x01, 0x05, 0x01, 0xEF, 0x68, 0x07, 0x88, 0xCC,   \
    0x33, 0x06, 0x54, 0xAB, 0x09, 0x01, 0x74, 0x77,   \
    0x49, 0x08, 0x93, 0xA8, 0x01, 0x07, 0xEF, 0x01,   \
    0x83, 0x09, 0x22, 0xCD, 0x09, 0x61, 0xB6, 0xFF

/* Below value is calculated as follows
 * sha256 (EXPECTED_SHA256_MEASUREMENT_VAL_TEST_0 || SW_SHA256_VAL_TEST_1)
 * i.e.
 * sha256(86bfbce7f88e77dab6bbfb923bb70e2411d374dc658db751c9bdec438f5cce54 ||
 *        010501EF680788CC330654AB09017477490893A80107EF01830922CD0961B6FF)
 *      = d2abc126eb5c259d30339c02d7494f04e2d449be81a96039560e5690b3daaf25
 */
#define EXPECTED_SHA256_MEASUREMENT_VAL_TEST_1        \
    0xd2, 0xab, 0xc1, 0x26, 0xeb, 0x5c, 0x25, 0x9d,   \
    0x30, 0x33, 0x9c, 0x02, 0xd7, 0x49, 0x4f, 0x04,   \
    0xe2, 0xd4, 0x49, 0xbe, 0x81, 0xa9, 0x60, 0x39,   \
    0x56, 0x0e, 0x56, 0x90, 0xb3, 0xda, 0xaf, 0x25    \

/* Below value is calculated as follows
 * sha512 (EXPECTED_SHA512_MEASUREMENT_VAL_TEST_0 || SW_SHA256_VAL_TEST_1)
 * i.e.
 * sha512(a634b5b6e5e9715d4788f72f1a39c3e2d2e103decfb8f8d622ccff8cb2e3e822...
 *        74316c4b8d662511cc1cf90a2456dff2b620d3bef0e0b956cf3acc78e658be40 ||
 *        010501EF680788CC330654AB09017477490893A80107EF01830922CD0961B6FF)
 *      = 532e19a7df21e77f6ae0e630dafb39678cdd745f309f1080b3fa887533310046...
 *        594f76b8fe5baec4ebe2e915024f344e88c043cd9014cdaad1c573bac34c56be
 */
#define EXPECTED_SHA512_MEASUREMENT_VAL_TEST_1        \
    0x53, 0x2e, 0x19, 0xa7, 0xdf, 0x21, 0xe7, 0x7f,   \
    0x6a, 0xe0, 0xe6, 0x30, 0xda, 0xfb, 0x39, 0x67,   \
    0x8c, 0xdd, 0x74, 0x5f, 0x30, 0x9f, 0x10, 0x80,   \
    0xb3, 0xfa, 0x88, 0x75, 0x33, 0x31, 0x00, 0x46,   \
    0x59, 0x4f, 0x76, 0xb8, 0xfe, 0x5b, 0xae, 0xc4,   \
    0xeb, 0xe2, 0xe9, 0x15, 0x02, 0x4f, 0x34, 0x4e,   \
    0x88, 0xc0, 0x43, 0xcd, 0x90, 0x14, 0xcd, 0xaa,   \
    0xd1, 0xc5, 0x73, 0xba, 0xc3, 0x4c, 0x56, 0xbe

#define SW_SHA512_VAL_TEST_2                          \
    0x8a, 0x66, 0x01, 0xf6, 0x70, 0x74, 0x8b, 0xe2,   \
    0x33, 0xff, 0x5d, 0x75, 0xd7, 0xea, 0x89, 0xa8,   \
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,   \
    0x01, 0x05, 0x01, 0xEF, 0x68, 0x07, 0x88, 0xCC,   \
    0x83, 0x09, 0x22, 0xCD, 0x09, 0x61, 0xB6, 0xFF,   \
    0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,   \
    0x56, 0x46, 0x58, 0x49, 0x99, 0x31, 0xcf, 0x59,   \
    0x7d, 0xbc, 0x3a, 0x4e, 0x68, 0x79, 0x8a, 0x1c

/* Below value is calculated as follows
 * sha256 (default_slot_measurement_value || SW_SHA512_VAL_TEST_2)
 * i.e.
 * sha256(0000000000000000000000000000000000000000000000000000000000000000 ||
 *        8a6601f670748be233ff5d75d7ea89a8bbbbbbbbbbbbbbbb010501EF680788CC8...
 *        30922CD0961B6FFbbbbbbbbbbbbbbbb564658499931cf597dbc3a4e68798a1c)
 *      = 75b220fd5ffcdbfc2073e4a02f8c53383c74bdf3b6ab9fb6b3d2bb7aa208c598
 */
#define EXPECTED_SHA256_MEASUREMENT_VAL_TEST_2        \
    0x75, 0xb2, 0x20, 0xfd, 0x5f, 0xfc, 0xdb, 0xfc,   \
    0x20, 0x73, 0xe4, 0xa0, 0x2f, 0x8c, 0x53, 0x38,   \
    0x3c, 0x74, 0xbd, 0xf3, 0xb6, 0xab, 0x9f, 0xb6,   \
    0xb3, 0xd2, 0xbb, 0x7a, 0xa2, 0x08, 0xc5, 0x98


/* Below value is calculated as follows
 * sha512 (default_slot_measurement_value || SW_SHA512_VAL_TEST_2)
 * i.e.
 * sha512(0000000000000000000000000000000000000000000000000000000000000000...
 *        0000000000000000000000000000000000000000000000000000000000000000 ||
 *        8a6601f670748be233ff5d75d7ea89a8bbbbbbbbbbbbbbbb010501EF680788CC8...
 *        30922CD0961B6FFbbbbbbbbbbbbbbbb564658499931cf597dbc3a4e68798a1c)
 *      = 8e175a1dcd79b8b51ce9e259c2568305b73f5f26f5673a8cf781a94598e44f67...
 *        fdf4926869ee7667e9120b5c1b97625cc96d347c23ce3c5f763bf1d9b54781f6
 */
#define EXPECTED_SHA512_MEASUREMENT_VAL_TEST_2        \
    0x8e, 0x17, 0x5a, 0x1d, 0xcd, 0x79, 0xb8, 0xb5,   \
    0x1c, 0xe9, 0xe2, 0x59, 0xc2, 0x56, 0x83, 0x05,   \
    0xb7, 0x3f, 0x5f, 0x26, 0xf5, 0x67, 0x3a, 0x8c,   \
    0xf7, 0x81, 0xa9, 0x45, 0x98, 0xe4, 0x4f, 0x67,   \
    0xfd, 0xf4, 0x92, 0x68, 0x69, 0xee, 0x76, 0x67,   \
    0xe9, 0x12, 0x0b, 0x5c, 0x1b, 0x97, 0x62, 0x5c,   \
    0xc9, 0x6d, 0x34, 0x7c, 0x23, 0xce, 0x3c, 0x5f,   \
    0x76, 0x3b, 0xf1, 0xd9, 0xb5, 0x47, 0x81, 0xf6

#define SW_SHA512_VAL_TEST_3                          \
    0x56, 0x46, 0x58, 0x49, 0x99, 0x31, 0xcf, 0x59,   \
    0x7d, 0xbc, 0x3a, 0x4e, 0x68, 0x79, 0x8a, 0x1c,   \
    0x01, 0x05, 0x01, 0xEF, 0x68, 0x07, 0x88, 0xCC,   \
    0x83, 0x09, 0x22, 0xCD, 0x09, 0x61, 0xB6, 0xFF,   \
    0x7d, 0xbc, 0x3a, 0x4e, 0x68, 0x79, 0x8a, 0x1c,   \
    0x01, 0x05, 0x01, 0xEF, 0x68, 0x07, 0x88, 0xCC,   \
    0x8a, 0x66, 0x01, 0xf6, 0x70, 0x74, 0x8b, 0xe2,   \
    0x83, 0x09, 0x22, 0xCD, 0x09, 0x61, 0xB6, 0xFF

/* Below value is calculated as follows
 * sha256 (EXPECTED_SHA256_MEASUREMENT_VAL_TEST_2 || SW_SHA512_VAL_TEST_3)
 * i.e.
 * sha256(75b220fd5ffcdbfc2073e4a02f8c53383c74bdf3b6ab9fb6b3d2bb7aa208c598 ||
 *        564658499931cf597dbc3a4e68798a1c010501EF680788CC830922CD0961B6FF7...
 *        dbc3a4e68798a1c010501EF680788CC8a6601f670748be2830922CD0961B6FF)
 *      = 79c3b9caf77ba7f32065770409608a024fa5459c6d10a7ca593ff14d9b37e83c
 */
#define EXPECTED_SHA256_MEASUREMENT_VAL_TEST_3        \
    0x79, 0xc3, 0xb9, 0xca, 0xf7, 0x7b, 0xa7, 0xf3,   \
    0x20, 0x65, 0x77, 0x04, 0x09, 0x60, 0x8a, 0x02,   \
    0x4f, 0xa5, 0x45, 0x9c, 0x6d, 0x10, 0xa7, 0xca,   \
    0x59, 0x3f, 0xf1, 0x4d, 0x9b, 0x37, 0xe8, 0x3c

/* Below value is calculated as follows
 * sha512 (EXPECTED_SHA512_MEASUREMENT_VAL_TEST_2 || SW_SHA512_VAL_TEST_3)
 * i.e.
 * sha512(8e175a1dcd79b8b51ce9e259c2568305b73f5f26f5673a8cf781a94598e44f67...
 *        fdf4926869ee7667e9120b5c1b97625cc96d347c23ce3c5f763bf1d9b54781f6 ||
 *        564658499931cf597dbc3a4e68798a1c010501EF680788CC830922CD0961B6FF...
 *        7dbc3a4e68798a1c010501EF680788CC8a6601f670748be2830922CD0961B6FF)
 *      = 79c3b9caf77ba7f32065770409608a024fa5459c6d10a7ca593ff14d9b37e83c
 */
#define EXPECTED_SHA512_MEASUREMENT_VAL_TEST_3           \
    0x69, 0x8f, 0xc1, 0x9d, 0xc0, 0xfb, 0x93, 0xc9,      \
    0x78, 0x31, 0x52, 0xd9, 0x33, 0x6f, 0x35, 0xa7,      \
    0x9a, 0x2d, 0x48, 0xdb, 0x45, 0xa8, 0xd4, 0xc4,      \
    0x8c, 0x0e, 0xef, 0xcb, 0xeb, 0xc0, 0x11, 0x0d,      \
    0xa2, 0xe4, 0x0f, 0x62, 0x78, 0x34, 0xdd, 0x8e,      \
    0x46, 0xa9, 0x2b, 0xaa, 0x23, 0x00, 0x6b, 0x36,      \
    0xc6, 0x79, 0xc0, 0x4e, 0x14, 0xca, 0x91, 0x3f,      \
    0xd2, 0xde, 0xe2, 0x38, 0x58, 0xd5, 0x43, 0xd2,

#ifdef __cplusplus
}
#endif

#endif /* __TEST_VALUES_H__ */
