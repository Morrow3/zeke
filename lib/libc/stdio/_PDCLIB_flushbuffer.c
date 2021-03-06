/*
 * _PDCLIB_flushbuffer(struct _PDCLIB_file_t *)
 *
 * This file is part of the Public Domain C Library (PDCLib).
 * Permission is granted to use, modify, and / or redistribute at will.
 */

#include <stdio.h>
#include <string.h>
#include <sys/_PDCLIB_glue.h>
#include <sys/_PDCLIB_io.h>

static int flushsubbuffer(FILE * stream, size_t length)
{
    _PDCLIB_fd_t pfd = stream->handle;
    char * buf = stream->buffer;
    size_t written = 0;
    int rv = 0;

    if (length > stream->bufsize) {
        length = stream->bufsize;
    }

    while (written != length) {
        size_t justWrote = 0;
        size_t toWrite = length - written;
        bool res;

        res = stream->ops->write(pfd, buf + written, toWrite, &justWrote);
        written += justWrote;
        stream->pos.offset += justWrote;

        if (!res) {
            stream->status |= _PDCLIB_ERRORFLAG;
            rv = EOF;
            break;
        }
    }

    memmove(buf, buf + written, stream->bufsize - written);
    if ((stream->bufidx - written) > stream->bufidx) {
        stream->bufidx = 0;
    } else {
        stream->bufidx -= written;
    }

    return rv;
}

#if defined(_PDCLIB_NEED_EOL_TRANSLATION)
#undef  _PDCLIB_NEED_EOL_TRANSLATION
#define _PDCLIB_NEED_EOL_TRANSLATION 1
#else
#define _PDCLIB_NEED_EOL_TRANSLATION 0
#endif

int _PDCLIB_flushbuffer(FILE * stream)
{
    /* if a text stream, and this platform needs EOL translation, well... */
    if (!(stream->status & _PDCLIB_FBIN) && _PDCLIB_NEED_EOL_TRANSLATION) {
        size_t pos;

        for (pos = 0; pos < stream->bufidx; pos++) {
            if (stream->buffer[pos] == '\n') {
                if (stream->bufidx == stream->bufend) {
                    /*
                     * buffer is full. Need to print out everything up till now
                     */
                    if (flushsubbuffer(stream, pos)) {
                        return EOF;
                    }

                    pos = 0;
                }

                /*
                 * we have spare space in buffer. Shift everything 1char and
                 * insert \r
                 */
                memmove(&stream->buffer[pos + 1], &stream->buffer[pos],
                        stream->bufidx - pos);
                stream->buffer[pos] = '\r';

                pos += 2;
                stream->bufidx++;
            }
        }
    }

    return flushsubbuffer(stream, stream->bufidx);
}
