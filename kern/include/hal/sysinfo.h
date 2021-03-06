/**
 *******************************************************************************
 * @file    sysinfo.h
 * @author  Olli Vanhoja
 * @brief   Header file for sysinfo.
 * @section LICENSE
 * Copyright (c) 2013, 2015 Olli Vanhoja <olli.vanhoja@cs.helsinki.fi>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************
 */

/**
 * @addtogroup HAL
 * @{
 */

#pragma once
#ifndef SYSINFO_H
#define SYSINFO_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    unsigned int fw;    /*!< Firmware version on platforms like rpi. */
    unsigned int mtype; /*!< ARM Linux Machine Type. */
    unsigned int hfp;   /*!< Hardware Floating Point support in kernel. */
    struct meminfo {
        size_t start;
        size_t size;
    } mem;
    char console[16];   /*!< Default tty. */
    char root[16 + 8];  /*!< Path and type of the root partition. */
} sysinfo_t;

extern sysinfo_t sysinfo;

void sysinfo_setmem(size_t start, size_t size);
void sysinfo_cmdline(const char * cmdline);

#endif /* SYSINFO_H */

/**
 * @}
 */
