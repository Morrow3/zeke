/**
 *******************************************************************************
 * @file    sys.c
 * @author  Olli Vanhoja
 *
 * @brief   System API.
 * @section LICENSE
 * Copyright (c) 2013 - 2015 Olli Vanhoja <olli.vanhoja@cs.helsinki.fi>
 * Copyright (c) 2012, 2013 Ninjaware Oy,
 *                          Olli Vanhoja <olli.vanhoja@ninjaware.fi>
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

#include <syscall.h>

#if defined(__ARM6__) || defined(__ARM6K__) || defined(__ARM6M__)
intptr_t syscall(uint32_t type, void * p)
{
    register uint32_t arg0 __asm__("r0") = type;
    register void * arg1 __asm__("r1") = p;
    int32_t scratch;

    __asm__ volatile (
        "SVC    #0\n\t"
#if defined(__ARM6M__)
        "DSB\n\t"           /* Ensure write is completed (architecturally
                             * required, but not strictly required for
                             * existing Cortex-M processors) */
        "ISB\n"             /* Ensure PendSV is executed */

#endif
        "MOV    %[res], r0\n\t"
        : [res]"=r" (scratch)
        : [typ]"r" (arg0), [arg]"r" (arg1)
        : "r2", "r3", "r4");

    return (intptr_t)scratch;
}
#else
#error Selected core is not suported by this libc
#endif
