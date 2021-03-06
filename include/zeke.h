/**
 *******************************************************************************
 * @file    zeke.h
 * @author  Olli Vanhoja
 * @brief   Zeke specific system functions.
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

/**
 * @addtogroup LIBC
 * @{
 */

#ifndef ZEKE_H
#define ZEKE_H

#ifndef KERNEL_INTERNAL
__BEGIN_DECLS

/**
 * Blocking sleep.
 * Sleeps time specified by seconds regardless of incoming signals.
 * Only a fatal signal may interrupt the sleep.
 */
unsigned bsleep(unsigned seconds);

/**
 * Blocking sleep.
 * Sleeps time specified by millisec regardless of incoming signals.
 * Only a fatal signal may interrupt the sleep.
 */
unsigned bmsleep(unsigned seconds);

unsigned msleep(unsigned millisec);

/**
 * Change root directory.
 * Change root directory to current process working directory.
 * Requires root permission and/or PRIV_VFS_CHROOT depending on configuration.
 */
int chrootcwd(void);

/**
 * Close all file descriptors above fildes.
 */
int closeall(int fildes);

__END_DECLS
#endif /* !KERNEL_INTERNAL */

#endif /* ZEKE_H */

/**
 * @}
 */
