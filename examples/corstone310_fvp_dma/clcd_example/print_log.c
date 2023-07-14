/*
 * Copyright (c) 2018-2021 Arm Limited. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include <stdio.h>
#include <stdarg.h>

#include "FreeRTOS.h"
#include "semphr.h"
#include "print_log.h"

SemaphoreHandle_t xUARTMutex;

static SemaphoreHandle_t prvCreateUARTMutex( void )
{
SemaphoreHandle_t xMutexHandle;
	xMutexHandle = xSemaphoreCreateMutex();
	configASSERT( xMutexHandle );
	return xMutexHandle;
}

void vUARTLockInit( void )
{
	xUARTMutex = prvCreateUARTMutex();
}

static BaseType_t xUARTLockAcquire()
{
	return xSemaphoreTake( xUARTMutex, portMAX_DELAY );
}

static BaseType_t xUARTLockRelease( void )
{
	return xSemaphoreGive( xUARTMutex );
}

void vLoggingPrintf(const char *format, ...)
{
    va_list args;
    BaseType_t schedulerState = xTaskGetSchedulerState();
    /* A UART lock is used here to ensure that there is
    * at most one task accessing UART at a time.
    */
    if (schedulerState != taskSCHEDULER_NOT_STARTED) {
        xUARTLockAcquire();
    }
    va_start( args, format );
    vprintf( format, args );
    va_end ( args );
    printf("\r\n");
    if (schedulerState != taskSCHEDULER_NOT_STARTED) {
        xUARTLockRelease();
    }
}

void vLoggingPrint(const char * message)
{
    BaseType_t schedulerState = xTaskGetSchedulerState();
    /* A UART lock is used here to ensure that there is
    * at most one task accessing UART at a time.
    */
    if (schedulerState != taskSCHEDULER_NOT_STARTED) {
        xUARTLockAcquire();
    }
    puts(message);
    printf("\r\n");
    if (schedulerState != taskSCHEDULER_NOT_STARTED) {
        xUARTLockRelease();
    }
}
