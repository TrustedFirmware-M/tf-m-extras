/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */
#ifndef _MX75_ARMOR_PROVISION_INFO_H
#define _MX75_ARMOR_PROVISION_INFO_H

/**
 * \file mx75_armor_provision_info.h
 *
 * \brief This file describes the format of mx75 series secure Flash
 *        provisioning data template
 */

/**The template structure of provisioning data blob
-----------------------------------------------------------
|                         Magic                            |
-----------------------------------------------------------
|Sub header stored num |Sub header num |Total size |Version|
-----------------------------------------------------------
|              Sub header 1:application info               |
-----------------------------------------------------------
|              Sub header 2:key derivation info            |
-----------------------------------------------------------
|              Sub header 3:lock info                      |
-----------------------------------------------------------
|              Sub header 4:counter info                   |
-----------------------------------------------------------
|              Sub header 5:configure info                 |
-----------------------------------------------------------
|              Detailed application info                   |
|                     description                          |
-----------------------------------------------------------
|              Detailed key derivation info                |
|                     description                          |
-----------------------------------------------------------
|              Detailed lock info                          |
|                     description                          |
-----------------------------------------------------------
|              Detailed counter info                       |
|                     description                          |
-----------------------------------------------------------
|              Detailed configure info                     |
|                     description                          |
-----------------------------------------------------------
As some provisioning data need not be stored, so the size of provisioning data
stored in memory is less than received provisioning data blob's size.
The template structure of provisioning data in memory is similar to above
provisioning data blob's structure.

The template structure of provisioning data stored in memory
-----------------------------------------------------------
|                         Magic                            |
-----------------------------------------------------------
|Sub header stored num |Sub header num |Total size |Version|
-----------------------------------------------------------
|              Sub header 1:application info               |
-----------------------------------------------------------
|              Sub header 2:key derivation info            |
-----------------------------------------------------------
|              Sub header 3:lock info                      |
-----------------------------------------------------------
|              Detailed application info                   |
|                     description                          |
-----------------------------------------------------------
|              Detailed key derivation info                |
|                     description                          |
-----------------------------------------------------------
|              Detailed lock info                          |
|                     description                          |
-----------------------------------------------------------

*/

#define SFPI_MAJOR_HEADER_SIZE  8
#define SFPI_SUB_HEADER_SIZE    8
#define ARMOR_APP_INFO_MAX_NUM  16
#define ARMOR_LKD_INFO_MAX_NUM  16
#define KEY_INFO_MAX_NUM        16
#define MC_INFO_MAX_NUM         16
#define MC_MAX_SIZE             4
#define CFG_INFO_MAX_NUM        0x200

#define PROV_ENABLE             1
#define PROV_DISABLE            0
/**
 * Sub items' header id of ArmorFlash provisioning information.
 */
typedef enum {
    SUB_ID_APP_INFO,
    SUB_ID_LOCK_INFO,
    SUB_ID_KEY_INFO,
    SUB_ID_MC_INFO,
    SUB_ID_CONFIG_INFO,
    SUB_ID_MAX_NUMBER,
} SubHeaderId;
/**
 * The modes of updating ArmorFlash's security keys.
 */
typedef enum {
    KEY_INFO_INJECT,
    KEY_INFO_IMPORT,
    KEY_INFO_GENERATE,
    KEY_INFO_DERIVE,
} UpdateKeyType;
/**
 * Lock status of writing/reading/locking down provisioning data.
 */
typedef enum {
    LOCK_INFO_WRITE_PROVISION = 0x01, /*!< Write provisioning data is locked,
                                           rewriting provisioning data is not
                                           allowed */
    LOCK_INFO_READ_PROVISION  = 0x02, /*!< Read provisioning data is locked,
                                           reading provisioning data is not
                                           allowed */
    LOCK_INFO_LOCK_PROVISION  = 0x04  /*!< Provision lock information is locked,
                                           updating ArmorFlash's lock down
                                           status is not allowed */
} LockInfoProvisionType;
/**
 * The types of HKDF specific input 'info'
 */
typedef enum {
    HKDF_0_MSG_UID,
    HKDF_0_MSG_PUF,
    HKDF_0_MSG_TRNG,
} DeriveKeyParamsSuite;


/**
 * \struct mx_app_data_t
 *
 * \brief Structure to store a certain application item's
 *        provisioning information.
 */
typedef struct {
    uint32_t app_id;    /*!< Application id */
    uint32_t key_id;    /*!< Application binded crypto key id */
    uint32_t zone_id:8, /*!< Application binded security zone id */
             mc_id:8,   /*!< Application binded monotonic counter id */
             reserved:16;
} mx_app_data_t;
/**
 * \struct mx_app_info_t
 *
 * \brief Structure holding provisioning information for applications.
 */
typedef struct {
    uint32_t id: 8,  /*!< Application provisioning information sub id */
             num: 8, /*!< The number of application items */
             reserved: 16;
    mx_app_data_t app_data[ARMOR_APP_INFO_MAX_NUM]; /*!< Buffer holding
                                                         application items'
                                                         provisioning
                                                         information */
} mx_app_info_t;

/**  provision for lock_info
 *
 *   DWORD 0: [07:00] ID, [31:08] reserved
 *   DWORD 1: [07:00] config_regs, [15:08] ind_key_lock,
 *            [23:16] ind_key_dis, [31:24] reserved
 *   DWORD 2: [15:00] datazone lock(bitwise), [31:16] provision (bitwise)
 **/
/**
 * \struct lock_data_t
 *
 */
typedef struct {
    uint32_t type: 8,   /*!< Lock down information type */
             option: 8, /*!< Lock down option */
             reserved: 16;
} lock_data_t;

/**
 * \struct lock_info_t
 *
 * \brief Structure holding provisioning information for
 *        ArmorFlash's lock down configuration.
 */
typedef struct {
    uint32_t id: 8,         /*!< Lock down provisioning information sub id */
             num: 8,        /*!< The actual number of lock down information */
             prvs_wr_en: 1, /*!< The lkd status of write provisioning */
             prvs_rd_en: 1, /*!< The lkd status of read provisioning */
             prvs_lkd_en:1, /*!< The lkd status of lock provisioning */
             reserved: 13;
    uint32_t lock_flags;    /*!< The lkd flags */
    lock_data_t lock_data[ARMOR_LKD_INFO_MAX_NUM]; /*!< Buffer holding lock
                                                        down information */
} lock_info_t;

/** provision for key_info
 * 
 *   DWORD 0: [07:00] ID, [15:08] key number, [31:16] Reserved
 *   key 0
 *     DWORD 1: [31:00] key id
 *     DWORD 2: [31:00] key derive message
 *     DWORD 3: [07:00] key derive params suite, [23:08] key length (in bytes),
 *              [31:24] key inject type
 *   key 1 ~ (key number -1)
 **/
/**
 * \struct key_data_t
 *
 * \brief Structure holding provisioning information used to derive a
 *        certain root key of ArmorFlash.
 */
typedef struct {
    uint32_t key_id;                 /*!< Root key id */
    uint32_t derive_message;         /*!< Specific information for root key
                                          derivation */
    uint32_t derive_params_suite: 8, /*!< Key derivation cipher algorithm */
             key_len: 16,            /*!< Derived root key length in bits */
             inject_type: 8;         /*!< The mode of synchronizing ArmorFlash's
                                          root key */
} key_data_t;
/**
 * \struct key_info_t
 *
 * \brief Structure holding provisioning information for ArmorFlash root keys
 *        derivation.
 */
typedef struct {
    uint32_t id: 8,              /*!< Key provisioning information sub id */
             num: 8,             /*!< The number of ArmorFlash root keys */
             reserved: 16;
    key_data_t key_data[KEY_INFO_MAX_NUM]; /*!< Buffer holding root keys'
                                                provisioning information */
} key_info_t;

/** provision for mc_info 
 *  
 *  DWORD 0: [07:00] ID, [15:08] mc number, [31:16] reserved
 *  mc 0
 *  DWORD 1: [31:00] mc value
 *  mc 1 ~ (mc number -1)
 **/
typedef struct {
    uint8_t value[MC_MAX_SIZE]; // power of two, '0' is not supported
} mc_data_t;
/**
 * \struct mc_info_t
 *
 * \brief Structure holding ArmorFlash monotonic counters' provisioning
 *        information.
 */
typedef struct {
    uint32_t id: 8,  /*!< Counter provisioning information sub id */
             num: 8, /*!< The number of ArmorFlash monotonic counters */
             reserved: 16;
    mc_data_t mc_data[MC_INFO_MAX_NUM]; /*!< Buffer holding monotonic counters'
                                             provisioning information */
} mc_info_t;

/** provision for config_info 
 *  
 *  DWORD 0: [07:00] ID, [31:08] reserved
 *  DWORD 1~88: configure data
 **/
/**
 * \struct config_info_t
 *
 * \brief Structure holding provisioning information used to configure
 *        ArmorFlash.
 */
typedef struct {
    uint32_t id: 8, /*!< Configuration provisioning information sub id */
             reserved: 24;
    uint8_t config_data[CFG_INFO_MAX_NUM]; /*!< Buffer holding ArmorFlash
                                                configuration' provisioning
                                                information */
} config_info_t;

/**
 * \struct provision_major_header_t
 *
 * \brief Structure holding the major header of ArmorFlash provisioning
 *        information.
 */
typedef struct {
        uint8_t magic[4];                /*!< The magic bytes of this
                                              provisioning information */
        uint32_t version: 8,             /*!< The version of this provisioning
                                              information */
                 total_size: 16,         /*!< The total size of this
                                              provisioning information */
                 sub_header_num: 4,      /*!< The number of this provisioning
                                              information's sub headers */
                 sub_table_store_num: 4; /*!< The number of this provisioning
                                              information's sub tables */
} provision_major_header_t;

/**
 * \struct provision_sub_header_t
 *
 * \brief Structure holding each sub item's header of ArmorFlash provisioning
 *        information.
 */
typedef struct {
    uint32_t id:         8, /*!< Sub item's header id */
             version:    8, /*!< Sub item's header version */
             store:      1, /*!< Sub item's header storage flag */
             reserved:  15;
    uint32_t table_size:16, /*!< Corresponding sub item's table size */
             offset:    16; /*!< The offset of corresponding sub item's table */
} provision_sub_header_t;

#endif /* _MX75_ARMOR_PROVISION_INFO_H */
