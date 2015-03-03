/**
 *******************************************************************************
 * @file    setuid.c
 * @author  Olli Vanhoja
 * @brief   Process credentials.
 * @section LICENSE
 * Copyright (c) 2014, 2015 Olli Vanhoja <olli.vanhoja@cs.helsinki.fi>
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

#include <stddef.h>
#include <sys/types.h>
#include <sys/_syscred.h>
#include <syscall.h>
#include <errno.h>
#include <sys/priv.h>
#include <unistd.h>

int setuid(uid_t uid)
{
    struct _proc_credctl_args ds = {
        .ruid = uid,
        .euid = uid,
        .suid = uid,
        .rgid = -1,
        .egid = -1,
        .sgid = -1
    };
    struct _proc_credctl_args ds_save = ds;
    int errno_save, err;

    if (uid < 0) {
        errno = EINVAL;
        return -1;
    }

    errno_save = errno;
    err = syscall(SYSCALL_PROC_CRED, &ds);
    if (err && errno == EPERM && ds.euid == ds_save.euid) {
        errno = errno_save;
        return 0;
    }

    return -1;
}