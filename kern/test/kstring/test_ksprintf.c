/**
 * @file test_ksprintf.c
 * @brief Test ksprintf.
 */

#include <stdint.h>
#include <stdarg.h>
#include <kunit.h>
#include <ktest_mib.h>
#include <kstring.h>

#define NTOSTR(s) _NTOSTR(s)
#define _NTOSTR(s) #s

#define JUNK "junkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunkjunk"

static void setup(void)
{
}

static void teardown(void)
{
}

static char * test_int(void)
{
    char actual[80] = JUNK;

    ksprintf(actual, sizeof(actual), "b%ie", (int)10);
    ku_assert_str_equal("String composed correctly.", actual, "b10e");

    return NULL;
}

static char * test_uint(void)
{
#define TSTRING1    "string"
#define UINTVAL     1337
#define EXPECTED TSTRING1 NTOSTR(UINTVAL) TSTRING1
    char actual[80] = JUNK;

    ksprintf(actual, sizeof(actual), TSTRING1 "%u" TSTRING1, (uint32_t)UINTVAL);

    ku_assert_str_equal("String composed correctly.", actual, EXPECTED);

#undef TSTRING1
#undef UINTVAL1
#undef EXPECTED

    return NULL;
}

static char * test_hex(void)
{
#define TSTRING1    "string"
#define HEXVALUE    0x00000500
#define EXPECTED TSTRING1 NTOSTR(HEXVALUE) TSTRING1
    char actual[80] = JUNK;

    ksprintf(actual, sizeof(actual), TSTRING1 "%x" TSTRING1,
             (uint32_t)HEXVALUE);

    ku_assert_str_equal("String composed correctly.", actual, EXPECTED);

#undef TSTRING1
#undef HEXVALUE
#undef EXPECTED

    return NULL;
}

static char * test_int64_t(void)
{
    char actual[80] = JUNK;

    ksprintf(actual, sizeof(actual), "b%llie", (int64_t)10);

    ku_assert_str_equal("String composed correctly.", actual, "b10e");

    return NULL;
}

static char * test_char(void)
{
#define TSTRING     "TEXT1"
#define TCHAR       'c'
    char actual[80] = JUNK;
    char final[sizeof(TSTRING) + 1] = TSTRING;
    final[sizeof(TSTRING) - 1] = TCHAR;
    final[sizeof(TSTRING)] = '\0';

    ksprintf(actual, sizeof(actual), TSTRING "%c", TCHAR);

    ku_assert_str_equal("Strings were concatenated correctly", actual, final);

#undef TSTRING
#undef TCHAR

    return NULL;
}

static char * test_string(void)
{
#define TSTRING1    "TEXT1"
#define TSTRING2    "TEXT2"
#define EXPECTED TSTRING1 TSTRING2 TSTRING1
    char actual[80] = JUNK;
    char expected[] = EXPECTED;

    ksprintf(actual, sizeof(actual), TSTRING1 "%s" TSTRING1, TSTRING2);

    ku_assert_str_equal("Strings were concatenated correctly", actual,
                        expected);

#undef TSTRING1
#undef TSTRING2
#undef EXPECTED

    return NULL;
}

static char * test_percent(void)
{
#define TSTRING     "TEXT1"
    char actual[80] = JUNK;
    char expected[] = "%" TSTRING "%";

    ksprintf(actual, sizeof(actual), "%%" TSTRING "%%");

    ku_assert_str_equal("Strings were concatenated correctly", actual,
                        expected);

#undef TSTRING

    return NULL;
}

static void all_tests(void)
{
    ku_mod_description("Test kstring functions.");
    ku_def_test(test_int, KU_RUN);
    ku_def_test(test_uint, KU_RUN);
    ku_def_test(test_hex, KU_RUN);
    ku_def_test(test_int64_t, KU_RUN);
    ku_def_test(test_char, KU_RUN);
    ku_def_test(test_string, KU_RUN);
    ku_def_test(test_percent, KU_RUN);
}

SYSCTL_TEST(kstring, ksprintf);
