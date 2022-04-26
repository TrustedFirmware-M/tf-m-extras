/*
 * Copyright (c) 2020-2022 Macronix International Co. LTD. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef _SECUREFLASH_LAYOUT_H_
#define _SECUREFLASH_LAYOUT_H_


extern void mx75_armor_set_vendor_operation(void *priv);

/** \brief Secure Flash name string. */
#define SECURE_FLASH_NAME     "mx75_armor"
/** \brief Secure Flash vendor specific implementation register function. */
#define SECURE_FLASH_VENDOR_OP_REGISTER    mx75_armor_set_vendor_operation

/** \brief The number of ArmorFlash applications.
 *         This is defined based on actual application numbers
 */
#define APP_INFO_MAX_NUM 16
/** \brief If multi-client(or multi-application) isolation is defined,
 *         the number of clients,
 *         and the layout of secure Flash memory region should be defined.
 *         Here takes four applications for example.
 */
#if defined(MULTI_CLIENT_ISOLATION) /*!< Enable multi-client isolation */
/* multi-client secure flash layout*/
#define SECURE_FLASH_CLIENT_NUM (4)
/*!< Client id 0 */
#define SECURE_FLASH_CLIENT0_ID                (0x00000001)
/*!< Start address of security memory region allocated for Client id 0 */
#define SECURE_FLASH_CLIENT0_AREA_START_ADDR   (0)
/*!< The size of security memory region allocated for Client id 0 */
#define SECURE_FLASH_CLIENT0_AREA_SIZE         (0x40000 * 4)
#define SECURE_FLASH_CLIENT0_SECTORS_PER_BLOCK (4)
/*!< Client id 1 */
#define SECURE_FLASH_CLIENT1_ID                (0x00000002)
/*!< Start address of security memory region allocated for Client id 1 */
#define SECURE_FLASH_CLIENT1_AREA_START_ADDR   (0x40000 * 4)
/*!< The size of security memory region allocated for Client id 1 */
#define SECURE_FLASH_CLIENT1_AREA_SIZE         (0x40000 * 4)
#define SECURE_FLASH_CLIENT1_SECTORS_PER_BLOCK (4)
/*!< Client id 2 */
#define SECURE_FLASH_CLIENT2_ID                (0x00000003)
/*!< Start address of security memory region allocated for Client id 2 */
#define SECURE_FLASH_CLIENT2_AREA_START_ADDR   (0x40000 * 8)
/*!< The size of security memory region allocated for Client id 2 */
#define SECURE_FLASH_CLIENT2_AREA_SIZE         (0x40000 * 4)
#define SECURE_FLASH_CLIENT2_SECTORS_PER_BLOCK (4)
/*!< Client id 3 */
#define SECURE_FLASH_CLIENT3_ID                (0x00000004)
/*!< Start address of security memory region allocated for Client id 3 */
#define SECURE_FLASH_CLIENT3_AREA_START_ADDR   (0x40000 * 12)
/*!< The size of security memory region allocated for Client id 3 */
#define SECURE_FLASH_CLIENT3_AREA_SIZE         (0x40000 * 4)
#define SECURE_FLASH_CLIENT3_SECTORS_PER_BLOCK (4)

#else /*!< Disable multi-client isolation */
/*!< Start address of secure Flash's security memory region */
#define SECURE_FLASH_START_ADDR                (0)
/*!< The total size of secure Flash's security memory region */
#define SECURE_FLASH_SIZE                      (0x400000)
/*!< The number of sectors of per secure Flash block */
#define SECURE_FLASH_SECTORS_PER_BLOCK         (4)
#endif
/*!< The size of secure Flash's sector */
#define SECURE_FLASH_SECTOR_SIZE               (0x1000)
/*!< The erase value of secure Flash */
#define SECURE_FLASH_ERASED_VALUE              (0xFF)
/*!< The backend secure Flash of ETSS partition */
#define TFM_ETSS_SECURE_FLASH_DEV              TFM_Secure_FLASH0
/*!< The program unit of secure Flash */
#define SECURE_FLASH_PROGRAM_UNIT              (0x20)

/** \brief Platform specific SPI driver.
 *
 */
#define SPI_NOR_HOST_DRIVER                    (Driver_SPI3)

#endif /* _SECUREFLASH_LAYOUT_H_ */
