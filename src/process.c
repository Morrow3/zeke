/**
 *******************************************************************************
 * @file    process.c
 * @author  Olli Vanhoja
 * @brief   Kernel process management source file. This file is responsible for
 *          thread creation and management.
 * @section LICENSE
 * Copyright (c) 2013 Olli Vanhoja <olli.vanhoja@cs.helsinki.fi>
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

/** @addtogroup Process
  * @{
  */

#define KERNEL_INTERNAL 1
#include <sched.h>
#include <syscalldef.h>
#include <syscall.h>
#include <errno.h>
#include <process.h>

volatile pid_t current_process_id;

int process_replace(pid_t pid, void * image, size_t size);

/**
 * Initialize a new process.
 * @param image Process image to be loaded.
 * @param size  Size of the image.
 * @return  PID; -1 if unable to initialize.
 */
pid_t process_init(void * image, size_t size)
{
    return -1;
}

/**
 * Create a new process.
 * @param pid   Process id.
 * @return  New PID; -1 if unable to fork.
 */
pid_t process_fork(pid_t pid)
{
    return -1;
}

int process_kill(void)
{
    return -1;
}

/**
 * Replace the image of a given process with a new one.
 * The new image must be mapped in kernel memory space.
 * @param pid   Process id.
 * @param image Process image to be loaded.
 * @param size  Size of the image.
 * @return  Value other than zero if unable to replace process.
 */
int process_replace(pid_t pid, void * image, size_t size)
{
    return -1;
}

processInfo_t * process_get_struct(pid_t pid)
{
    return 0;
}

/**
 * Get page table descriptor of a process.
 * @param pid Process ID.
 * @return Page table descriptor.
 */
mmu_pagetable_t * process_get_pptable(pid_t pid)
{
    mmu_pagetable_t * pptable;

    if (pid == 0) {
        pptable = &mmu_pagetable_master;
    } else {
        pptable = process_get_struct(pid)->pptable;
    }

    return pptable;
}

/**
 * Update process system state.
 * @note Updates current_process_id.
 */
void process_update(void)
{
    current_process_id = current_thread->pid_owner;
}

uint32_t proc_syscall(uint32_t type, void * p)
{
    switch(type) {
    case SYSCALL_PROC_EXEC:
        current_thread->errno = ENOSYS;
        return -1;

    case SYSCALL_PROC_FORK:
        current_thread->errno = ENOSYS;
        return -2;

    case SYSCALL_PROC_WAIT:
        current_thread->errno = ENOSYS;
        return -3;

    case SYSCALL_PROC_EXIT:
        current_thread->errno = ENOSYS;
        return -4;

    case SYSCALL_PROC_GETUID:
        current_thread->errno = ENOSYS;
        return -5;

    case SYSCALL_PROC_GETEUID:
        current_thread->errno = ENOSYS;
        return -6;

    case SYSCALL_PROC_GETGID:
        current_thread->errno = ENOSYS;
        return -7;

    case SYSCALL_PROC_GETEGID:
        current_thread->errno = ENOSYS;
        return -8;

    case SYSCALL_PROC_GETPID:
        current_thread->errno = ENOSYS;
        return -9;

    case SYSCALL_PROC_GETPPID:
        current_thread->errno = ENOSYS;
        return -10;

    case SYSCALL_PROC_SIGNAL:
        current_thread->errno = ENOSYS;
        return -11;

    case SYSCALL_PROC_KILL:
        current_thread->errno = ENOSYS;
        return -12;

    case SYSCALL_PROC_ALARM:
        current_thread->errno = ENOSYS;
        return -13;

    case SYSCALL_PROC_CHDIR:
        current_thread->errno = ENOSYS;
        return -14;

    default:
        return (uint32_t)NULL;
    }
}

/**
  * @}
  */