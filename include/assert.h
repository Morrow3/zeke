/* 7.2 Diagnostics <assert.h>
 *
 * This file is part of the Public Domain C Library (PDCLib).
 * Permission is granted to use, modify, and / or redistribute at will.
 */

/**
 * @addtogroup LIBC
 * @{
 */

#ifndef _PDCLIB_ASSERT_H
#define _PDCLIB_ASSERT_H _PDCLIB_ASSERT_H

#include <sys/_PDCLIB_aux.h>
#include <sys/_PDCLIB_config.h>
__BEGIN_DECLS

/**
 * @addtogroup assert
 * Abort the program if assertion is false.
 * @{
 */

/* Functions _NOT_ tagged noreturn as this hampers debugging */
void _PDCLIB_assert99( char const * const, char const * const, char const * const );
void _PDCLIB_assert89( char const * const );

/* If NDEBUG is set, assert() is a null operation. */
#undef assert

#ifdef NDEBUG
#define assert( ignore ) do { \
        if(!(expression)) { _PDCLIB_UNREACHABLE; } \
    } while(0)

#elif _PDCLIB_C_MIN(99)
/**
 * Assertion.
 * If the macro NDEBUG is not defined, the assert() macro generates an error
 * check that aborts the program if the condition is false.
 */
#define assert(expression) \
    do { if(!(expression)) { \
        _PDCLIB_assert99("Assertion failed: " _PDCLIB_symbol2string(expression)\
                         ", function ", __func__, \
                         ", file " __FILE__ \
                         ", line " _PDCLIB_symbol2string( __LINE__ ) \
                         "." _PDCLIB_endl ); \
        _PDCLIB_UNREACHABLE; \
      } \
    } while(0)

#else
#define assert(expression) \
    do { if(!(expression)) { \
        _PDCLIB_assert89("Assertion failed: " _PDCLIB_symbol2string(expression)\
                         ", file " __FILE__ \
                         ", line " _PDCLIB_symbol2string( __LINE__ ) \
                         "." _PDCLIB_endl ); \
        _PDCLIB_UNREACHABLE; \
      } \
    } while(0)
#endif

/**
 * @}
 */

__END_DECLS
#endif

/**
 * @}
 */
