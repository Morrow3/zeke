#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <dirent.h>
#include "punit.h"

DIR * dp;

static void setup()
{
    dp = NULL;
}

static void teardown()
{
    closedir(dp);
}

static char * test_opendir()
{
    DIR * dp;

    dp = opendir("/bin");
    pu_assert("dir opened", dp != NULL);

    return NULL;
}

static char * test_readdir()
{
    DIR * dp;
    struct dirent * dep;

    dp = opendir("/bin");

    dep = readdir(dp);
    pu_assert("got dirent", dep != NULL);

    do {
        printf("%s ", dep->d_name);
    } while ((dep = readdir(dp)));
    printf("\n");

    return NULL;
}

static void all_tests()
{
    pu_def_test(test_opendir, PU_RUN);
    pu_def_test(test_readdir, PU_RUN);
}

int main(int argc, char **argv)
{
    return pu_run_tests(&all_tests);
}
