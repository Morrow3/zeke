/**
 *******************************************************************************
 * @file    kerror_buf.c
 * @author  Olli Vanhoja
 * @brief   Kernel buffer error message logger.
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

#include <kstring.h>
#include <kerror.h>
#include <sys/linker_set.h>
#include <strcbuf.h>

static char kerror_strbuf[configKERROR_BUF_SIZE];
static struct strcbuf klogbuf = {
    .start = 0,
    .end = 0,
    .len = sizeof(kerror_strbuf),
    .data = kerror_strbuf
};

static void kerror_buf_init(void)
{
    klogbuf.start = 0;
    klogbuf.end = 0;
}

/*
 * This is extern in purpose as kerror.c is using this before kerror is
 * initialized properly.
 */
void kerror_buf_puts(const char * str)
{
    strcbuf_insert(&klogbuf, str, configKERROR_MAXLEN);
}

static void kerror_buf_flush(void)
{
    char buf[configKERROR_MAXLEN];

    while (strcbuf_getline(&klogbuf, buf, sizeof(buf)))
        kputs(buf);
}

static const struct kerror_klogger klogger_buf = {
    .id     = KERROR_BUF,
    .init   = &kerror_buf_init,
    .puts   = &kerror_buf_puts,
    .read   = 0,
    .flush  = &kerror_buf_flush
};
DATA_SET(klogger_set, klogger_buf);
