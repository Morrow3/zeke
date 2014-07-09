/**
 *******************************************************************************
 * @file    stat.c
 * @author  Olli Vanhoja
 * @brief   File status functions.
 * @section LICENSE
 * Copyright (c) 2014 Olli Vanhoja <olli.vanhoja@cs.helsinki.fi>
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

#include <stdarg.h>
#if 0
#include <string.h>
#endif
#include <kstring.h>
#include <time.h>
#define strlen(x) strlenn(x, 4096) /* TODO REMOVE ME */
#include <syscall.h>
#include <fcntl.h>
#include <sys/stat.h>

int fstat(int fildes, struct stat * buf)
{
    struct _fs_stat_args args = {
        .fd = fildes,
        .buf = buf,
        .flags = AT_FDARG | O_EXEC
    };

    return syscall(SYSCALL_FS_STAT, &args);
}

int fstatat(int fd, const char * restrict path,
            struct stat * restrict buf, int flag)
{
    struct _fs_stat_args args = {
        .fd = fd,
        .path = path,
        .path_len = strlen(path) + 1,
        .buf = buf,
        .flags = AT_FDARG | flag
    };

    return syscall(SYSCALL_FS_STAT, &args);
}

int lstat(const char * restrict path, struct stat * restrict buf)
{
    struct _fs_stat_args args = {
        .path = path,
        .path_len = strlen(path) + 1,
        .buf = buf,
        .flags = AT_SYMLINK_NOFOLLOW
    };

    return syscall(SYSCALL_FS_STAT, &args);
}

int stat(const char * restrict path, struct stat * restrict buf)
{
    struct _fs_stat_args args = {
        .path = path,
        .path_len = strlen(path) + 1,
        .buf = buf
    };

    return syscall(SYSCALL_FS_STAT, &args);
}

int mkdir(const char * path, mode_t mode)
{
    struct _fs_mkdir_args args = {
        .path = path,
        .path_len = strlen(path) + 1,
        .mode = mode
    };

    return syscall(SYSCALL_FS_MKDIR, &args);
}
