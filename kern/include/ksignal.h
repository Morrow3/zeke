/**
 *******************************************************************************
 * @file    ksignal.h
 * @author  Olli Vanhoja
 *
 * @brief   Header file for thread Signal Management in kernel (ksignal.c).
 * @section LICENSE
 * Copyright (c) 2013, 2014 Olli Vanhoja <olli.vanhoja@cs.helsinki.fi>
 * Copyright (c) 2012, 2013, Ninjaware Oy, Olli Vanhoja <olli.vanhoja@ninjaware.fi>
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

#ifndef KSIGNAL_H
#define KSIGNAL_H

#include <sys/tree.h>
#include <stdint.h>
#include <signal.h>

struct ksigaction {
    int signum;
    struct sigaction;
    RB_ENTRY(ksigaction) _entry;
};

RB_HEAD(sigaction_tree, ksigaction);

/**
 * Thread signals struct.
 */
struct signals {
    sigset_t s_block;       /*!< List of blocked signals. */
    sigset_t s_wait;        /*!< Signal wait mask. */
    sigset_t s_pending;     /*!< Signals pending for handling. */
    struct sigaction_tree sa_tree;
};

/**
 * Get signal boolean value from signals variable.
 * @param signals   is a signals variable.
 * @param signum    is the signal number.
 * @return Rerturns 0 if signal is not set; 1 if signal is set.
 */
#define KSIGNAL_GET_VALUE(signals, signum) ((signals >> signum) & 0x1)

/**
 * Get signal mask.
 * @param signum is a signal number.
 * @return Returns a bit mask for signals variable.
 */
#define KSIGNAL_GET_MASK(signum) (0x1 << signum)

RB_PROTOTYPE(sigaction_tree, ksigaction, _entry, signum_comp);
int signum_comp(struct ksigaction * a, struct ksigaction * b);

#endif /* KSIGNAL_H */

