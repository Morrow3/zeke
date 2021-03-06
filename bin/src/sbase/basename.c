/* See LICENSE file for copyright and license details. */
#include <libgen.h>
#include <stdio.h>
#include <string.h>

#include "util.h"

static void
usage(void)
{
    eprintf("usage: %s path [suffix]\n", argv0);
}

int
main(int argc, char *argv[])
{
    char *p;

    argv0 = argv[0], argc--, argv++;

    if (argc != 1 && argc != 2)
        usage();

    p = basename(argv[0]);
    if (argc == 2) {
        ssize_t off;

        off = strlen(p) - strlen(argv[1]);
        if (off > 0 && !strcmp(p + off, argv[1]))
            p[off] = '\0';
    }
    puts(p);

    return fshut(stdout, "<stdout>");
}
