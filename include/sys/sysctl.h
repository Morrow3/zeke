/**
 *******************************************************************************
 * @file    sysctl.h
 * @author  Olli Vanhoja
 *
 * @brief   Sysctl headers.
 * @section LICENSE
 * Copyright (c) 2014 Olli Vanhoja <olli.vanhoja@cs.helsinki.fi>
 * Copyright (c) 1989, 1993
 *        The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Mike Karels at Berkeley Software Design, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *        @(#)sysctl.h        8.1 (Berkeley) 6/2/93
 */

#ifndef _SYS_SYSCTL_H_
#define _SYS_SYSCTL_H_

#include <stddef.h>
#include <stdint.h>
#include <sys/queue.h>

struct thread;
/*
 * Definitions for sysctl call.  The sysctl call uses a hierarchical name
 * for objects that can be examined or modified.  The name is expressed as
 * a sequence of integers.  Like a file path name, the meaning of each
 * component depends on its place in the hierarchy.  The top-level and kern
 * identifiers are defined here, and other identifiers are defined in the
 * respective subsystem header files.
 */

#define CTL_MAXNAME     24 /* largest number of components supported */

/*
 * Each subsystem defined by sysctl defines a list of variables
 * for that subsystem. Each name is either a node with further
 * levels defined below it, or it is a leaf of some particular
 * type given below. Each sysctl level defines a set of name/type
 * pairs to be used by sysctl(8) in manipulating the subsystem.
 */
struct ctlname {
    char * ctl_name; /* subsystem name */
    int ctl_type;  /* type of name */
};

#define CTLTYPE         0xf      /* mask for the type */
#define CTLTYPE_NODE    1        /* name is a node */
#define CTLTYPE_INT     2        /* name describes an integer */
#define CTLTYPE_STRING  3        /* name describes a string */
#define CTLTYPE_S64     4        /* name describes a signed 64-bit number */
#define CTLTYPE_OPAQUE  5        /* name describes a structure */
#define CTLTYPE_STRUCT  CTLTYPE_OPAQUE        /* name describes a structure */
#define CTLTYPE_UINT    6        /* name describes an unsigned integer */
#define CTLTYPE_LONG    7        /* name describes a long */
#define CTLTYPE_ULONG   8        /* name describes an unsigned long */
#define CTLTYPE_U64     9        /* name describes an unsigned 64-bit number */

#define CTLFLAG_RD      0x80000000        /* Allow reads of variable */
#define CTLFLAG_WR      0x40000000        /* Allow writes to the variable */
#define CTLFLAG_RW      (CTLFLAG_RD|CTLFLAG_WR)
#define CTLFLAG_ANYBODY 0x10000000        /* All users can set this var */
#define CTLFLAG_SECURE  0x08000000        /* Permit set only if securelevel<=0 */
#define CTLFLAG_PRISON  0x04000000        /* Prisoned roots can fiddle */
#define CTLFLAG_DYN     0x02000000        /* Dynamic oid - can be freed */
#define CTLFLAG_SKIP    0x01000000        /* Skip this sysctl when listing */
#define CTLMASK_SECURE  0x00F00000        /* Secure level */
#define CTLFLAG_TUN     0x00080000        /* Tunable variable */
#define CTLFLAG_RDTUN   (CTLFLAG_RD|CTLFLAG_TUN)
#define CTLFLAG_RWTUN   (CTLFLAG_RW|CTLFLAG_TUN)
#define CTLFLAG_MPSAFE  0x00040000        /* Handler is MP safe */
#define CTLFLAG_VNET    0x00020000        /* Prisons with vnet can fiddle */
#define CTLFLAG_DYING   0x00010000        /* Oid is being removed */
#define CTLFLAG_CAPRD   0x00008000        /* Can be read in capability mode */
#define CTLFLAG_CAPWR   0x00004000        /* Can be written in capability mode */
#define CTLFLAG_STATS   0x00002000        /* Statistics, not a tuneable */
#define CTLFLAG_CAPRW   (CTLFLAG_CAPRD|CTLFLAG_CAPWR)

/*
 * Secure level.   Note that CTLFLAG_SECURE == CTLFLAG_SECURE1.
 *
 * Secure when the securelevel is raised to at least N.
 */
#define        CTLSHIFT_SECURE        20
#define        CTLFLAG_SECURE1        (CTLFLAG_SECURE | (0 << CTLSHIFT_SECURE))
#define        CTLFLAG_SECURE2        (CTLFLAG_SECURE | (1 << CTLSHIFT_SECURE))
#define        CTLFLAG_SECURE3        (CTLFLAG_SECURE | (2 << CTLSHIFT_SECURE))

/*
 * USE THIS instead of a hardwired number from the categories below
 * to get dynamically assigned sysctl entries using the linker-set
 * technology. This is the way nearly all new sysctl variables should
 * be implemented.
 * e.g. SYSCTL_INT(_parent, OID_AUTO, name, CTLFLAG_RW, &variable, 0, "");
 */
#define OID_AUTO    (-1)

#ifdef KERNEL_INTERNAL
#include <sys/linker_set.h>

#define SYSCTL_HANDLER_ARGS struct sysctl_oid * oidp, void *arg1, \
    intptr_t arg2, struct sysctl_req * req

/* definitions for sysctl_req 'lock' member */
#define REQ_UNWIRED 1
#define REQ_WIRED   2

/*
 * This describes the access space for a sysctl request.  This is needed
 * so that we can use the interface from the kernel or from user-space.
 */
struct sysctl_req {
    struct thread * td; /* used for access checking */
    int lock;           /* wiring state */
    void * oldptr;
    size_t oldlen;
    size_t oldidx;
    int (*oldfunc)(struct sysctl_req *, const void *, size_t);
    void * newptr;
    size_t newlen;
    size_t newidx;
    int (*newfunc)(struct sysctl_req *, void *, size_t);
    size_t validlen;
    int flags;
};

SLIST_HEAD(sysctl_oid_list, sysctl_oid);

/*
 * This describes one "oid" in the MIB tree.  Potentially more nodes can
 * be hidden behind it, expanded by the handler.
 */
struct sysctl_oid {
    struct sysctl_oid_list * oid_parent;
    SLIST_ENTRY(sysctl_oid) oid_link;
    int oid_number;
    unsigned int oid_kind;
    void * oid_arg1;
    intptr_t oid_arg2;
    const char * oid_name;
    int (*oid_handler)(SYSCTL_HANDLER_ARGS);
    const char * oid_fmt;
    int oid_refcnt;
    unsigned int oid_running;
    const char * oid_descr;
};

#define SYSCTL_IN(r, p, l)  (r->newfunc)(r, p, l)
#define SYSCTL_OUT(r, p, l) (r->oldfunc)(r, p, l)

int sysctl_handle_int(SYSCTL_HANDLER_ARGS);
int sysctl_handle_long(SYSCTL_HANDLER_ARGS);
int sysctl_handle_64(SYSCTL_HANDLER_ARGS);
int sysctl_handle_string(SYSCTL_HANDLER_ARGS);

/* Declare a static oid to allow child oids to be added to it. */
#define SYSCTL_DECL(name) \
    extern struct sysctl_oid_list sysctl_##name##_children

/* Hide these in macros. */
#define SYSCTL_CHILDREN(oid_ptr)                                        \
    (struct sysctl_oid_list *)(oid_ptr)->oid_arg1
#define SYSCTL_CHILDREN_SET(oid_ptr, val) (oid_ptr)->oid_arg1 = (val)
#define SYSCTL_STATIC_CHILDREN(oid_name) (&sysctl_##oid_name##_children)

/* === Structs and macros related to context handling. === */

#define SYSCTL_NODE_CHILDREN(parent, name) \
    sysctl_##parent##_##name##_children

/*
 * These macros provide type safety for sysctls.  SYSCTL_ALLOWED_TYPES()
 * defines a transparent union of the allowed types.  SYSCTL_ASSERT_TYPE()
 * and SYSCTL_ADD_ASSERT_TYPE() use the transparent union to assert that
 * the pointer matches the allowed types.
 *
 * The allow_0 member allows a literal 0 to be passed for ptr.
 */
#define        SYSCTL_ALLOWED_TYPES(type, decls)                        \
    union sysctl_##type {                                        \
        long allow_0;                                        \
        decls                                                \
    } __attribute__((__transparent_union__));                \
                                                                \
    static inline void *                                        \
        __sysctl_assert_##type(union sysctl_##type ptr)                \
    {                                                        \
        return (ptr.a);                                        \
    }                                                        \
    struct __hack

SYSCTL_ALLOWED_TYPES(INT, int *a; );
SYSCTL_ALLOWED_TYPES(UINT, unsigned int *a; );
SYSCTL_ALLOWED_TYPES(LONG, long *a; );
SYSCTL_ALLOWED_TYPES(ULONG, unsigned long *a; );
SYSCTL_ALLOWED_TYPES(INT64, int64_t *a; long long *b; );
SYSCTL_ALLOWED_TYPES(UINT64, uint64_t *a; unsigned long long *b; );

#ifdef notyet
#define        SYSCTL_ADD_ASSERT_TYPE(type, ptr)        \
    __sysctl_assert_ ## type (ptr)
#define        SYSCTL_ASSERT_TYPE(type, ptr, parent, name)        \
    _SYSCTL_ASSERT_TYPE(type, ptr, __LINE__, parent##_##name)
#else
#define        SYSCTL_ADD_ASSERT_TYPE(type, ptr)        ptr
#define        SYSCTL_ASSERT_TYPE(type, ptr, parent, name)
#endif
#define        _SYSCTL_ASSERT_TYPE(t, p, l, id)                \
    __SYSCTL_ASSERT_TYPE(t, p, l, id)
#define        __SYSCTL_ASSERT_TYPE(type, ptr, line, id)                        \
    static inline void                                                \
    sysctl_assert_##line##_##id(void)                                \
    {                                                                \
        (void)__sysctl_assert_##type(ptr);                        \
    }                                                                \
    struct __hack

#ifndef NO_SYSCTL_DESCR
#define        __DESCR(d) d
#else
#define        __DESCR(d) ""
#endif

/* This constructs a "raw" MIB oid. */
#define        SYSCTL_OID(parent, nbr, name, kind, a1, a2, handler, fmt, descr)\
    static struct sysctl_oid sysctl__##parent##_##name = {                \
        &sysctl_##parent##_children,                                \
        { NULL },                                                \
        nbr,                                                        \
        kind,                                                        \
        a1,                                                        \
        a2,                                                        \
        #name,                                                        \
        handler,                                                \
        fmt,                                                        \
        0,                                                        \
        0,                                                        \
        __DESCR(descr)                                                \
    };                                                        \
    DATA_SET(sysctl_set, sysctl__##parent##_##name)

#define SYSCTL_ADD_OID(ctx, parent, nbr, name, kind, a1, a2, handler, fmt, descr) \
        sysctl_add_oid(ctx, parent, nbr, name, kind, a1, a2, handler, fmt, __DESCR(descr))

/* This constructs a node from which other oids can hang. */
#define SYSCTL_NODE(parent, nbr, name, access, handler, descr)                    \
    struct sysctl_oid_list SYSCTL_NODE_CHILDREN(parent, name);            \
    SYSCTL_OID(parent, nbr, name, CTLTYPE_NODE|(access),                    \
    (void*)&SYSCTL_NODE_CHILDREN(parent, name), 0, handler, "N", descr)

#define SYSCTL_ADD_NODE(ctx, parent, nbr, name, access, handler, descr)            \
    sysctl_add_oid(ctx, parent, nbr, name, CTLTYPE_NODE|(access),            \
            NULL, 0, handler, "N", __DESCR(descr))

/* Oid for a string.  len can be 0 to indicate '\0' termination. */
#define        SYSCTL_STRING(parent, nbr, name, access, arg, len, descr) \
        SYSCTL_OID(parent, nbr, name, CTLTYPE_STRING|(access), \
                arg, len, sysctl_handle_string, "A", descr)

#define        SYSCTL_ADD_STRING(ctx, parent, nbr, name, access, arg, len, descr)  \
        sysctl_add_oid(ctx, parent, nbr, name, CTLTYPE_STRING|(access),            \
        arg, len, sysctl_handle_string, "A", __DESCR(descr))

/* Oid for an int.  If ptr is NULL, val is returned. */
#define        SYSCTL_INT(parent, nbr, name, access, ptr, val, descr)                \
        SYSCTL_ASSERT_TYPE(INT, ptr, parent, name);                        \
        SYSCTL_OID(parent, nbr, name,                                        \
            CTLTYPE_INT | CTLFLAG_MPSAFE | (access),                        \
            ptr, val, sysctl_handle_int, "I", descr)

#define        SYSCTL_ADD_INT(ctx, parent, nbr, name, access, ptr, val, descr)        \
        sysctl_add_oid(ctx, parent, nbr, name,                                \
            CTLTYPE_INT | CTLFLAG_MPSAFE | (access),                        \
            SYSCTL_ADD_ASSERT_TYPE(INT, ptr), val,                        \
            sysctl_handle_int, "I", __DESCR(descr))

/* Oid for an unsigned int.  If ptr is NULL, val is returned. */
#define        SYSCTL_UINT(parent, nbr, name, access, ptr, val, descr)                \
        SYSCTL_ASSERT_TYPE(UINT, ptr, parent, name);                        \
        SYSCTL_OID(parent, nbr, name,                                        \
            CTLTYPE_UINT | CTLFLAG_MPSAFE | (access),                        \
            ptr, val, sysctl_handle_int, "IU", descr)

#define        SYSCTL_ADD_UINT(ctx, parent, nbr, name, access, ptr, val, descr) \
        sysctl_add_oid(ctx, parent, nbr, name,                                \
            CTLTYPE_UINT | CTLFLAG_MPSAFE | (access),                        \
            SYSCTL_ADD_ASSERT_TYPE(UINT, ptr), val,                        \
            sysctl_handle_int, "IU", __DESCR(descr))

/* Oid for a long.  The pointer must be non NULL. */
#define        SYSCTL_LONG(parent, nbr, name, access, ptr, val, descr)                \
        SYSCTL_ASSERT_TYPE(LONG, ptr, parent, name);                        \
        SYSCTL_OID(parent, nbr, name,                                        \
            CTLTYPE_LONG | CTLFLAG_MPSAFE | (access),                        \
            ptr, val, sysctl_handle_long, "L", descr)

#define        SYSCTL_ADD_LONG(ctx, parent, nbr, name, access, ptr, descr)        \
        sysctl_add_oid(ctx, parent, nbr, name,                                \
            CTLTYPE_LONG | CTLFLAG_MPSAFE | (access),                        \
            SYSCTL_ADD_ASSERT_TYPE(LONG, ptr), 0,                        \
            sysctl_handle_long,        "L", __DESCR(descr))

/* Oid for an unsigned long.  The pointer must be non NULL. */
#define        SYSCTL_ULONG(parent, nbr, name, access, ptr, val, descr)        \
        SYSCTL_ASSERT_TYPE(ULONG, ptr, parent, name);                        \
        SYSCTL_OID(parent, nbr, name,                                        \
            CTLTYPE_ULONG | CTLFLAG_MPSAFE | (access),                        \
            ptr, val, sysctl_handle_long, "LU", descr)

#define        SYSCTL_ADD_ULONG(ctx, parent, nbr, name, access, ptr, descr)        \
        sysctl_add_oid(ctx, parent, nbr, name,                                \
            CTLTYPE_ULONG | CTLFLAG_MPSAFE | (access),                        \
            SYSCTL_ADD_ASSERT_TYPE(ULONG, ptr), 0,                        \
            sysctl_handle_long, "LU", __DESCR(descr))

/* Oid for a 64-bit unsigned counter(9).  The pointer must be non NULL. */
#define        SYSCTL_COUNTER_U64(parent, nbr, name, access, ptr, val, descr)        \
        SYSCTL_ASSERT_TYPE(UINT64, ptr, parent, name);                        \
        SYSCTL_OID(parent, nbr, name,                                        \
            CTLTYPE_U64 | CTLFLAG_MPSAFE | (access),                        \
            ptr, val, sysctl_handle_counter_u64, "QU", descr)

#define        SYSCTL_ADD_COUNTER_U64(ctx, parent, nbr, name, access, ptr, descr)\
        sysctl_add_oid(ctx, parent, nbr, name,                                \
            CTLTYPE_U64 | CTLFLAG_MPSAFE | (access),                        \
            SYSCTL_ADD_ASSERT_TYPE(UINT64, ptr), 0,                        \
            sysctl_handle_counter_u64, "QU", __DESCR(descr))

/* Oid for an opaque object.  Specified by a pointer and a length. */
#define        SYSCTL_OPAQUE(parent, nbr, name, access, ptr, len, fmt, descr) \
        SYSCTL_OID(parent, nbr, name, CTLTYPE_OPAQUE|(access), \
                ptr, len, sysctl_handle_opaque, fmt, descr)

#define        SYSCTL_ADD_OPAQUE(ctx, parent, nbr, name, access, ptr, len, fmt, descr)\
        sysctl_add_oid(ctx, parent, nbr, name, CTLTYPE_OPAQUE|(access),            \
        ptr, len, sysctl_handle_opaque, fmt, __DESCR(descr))

/* Oid for a struct.  Specified by a pointer and a type. */
#define        SYSCTL_STRUCT(parent, nbr, name, access, ptr, type, descr) \
        SYSCTL_OID(parent, nbr, name, CTLTYPE_OPAQUE|(access), \
                ptr, sizeof(struct type), sysctl_handle_opaque, \
                "S," #type, descr)

#define        SYSCTL_ADD_STRUCT(ctx, parent, nbr, name, access, ptr, type, descr) \
        sysctl_add_oid(ctx, parent, nbr, name, CTLTYPE_OPAQUE|(access),            \
        ptr, sizeof(struct type), sysctl_handle_opaque, "S," #type, __DESCR(descr))

/* Oid for a procedure.  Specified by a pointer and an arg. */
#define        SYSCTL_PROC(parent, nbr, name, access, ptr, arg, handler, fmt, descr) \
        CTASSERT(((access) & CTLTYPE) != 0);                                \
        SYSCTL_OID(parent, nbr, name, (access), \
                ptr, arg, handler, fmt, descr)

#define        SYSCTL_ADD_PROC(ctx, parent, nbr, name, access, ptr, arg, handler, fmt, descr) \
        sysctl_add_oid(ctx, parent, nbr, name, (access),                            \
        ptr, arg, handler, fmt, __DESCR(descr))

/*
 * A macro to generate a read-only sysctl to indicate the presense of optional
 * kernel features.
 */
#define        FEATURE(name, desc)                                                \
        SYSCTL_INT(_kern_features, OID_AUTO, name, CTLFLAG_RD | CTLFLAG_CAPRD, \
            NULL, 1, desc)

#endif /* KERNEL_INTERNAL */

/*
 * Top-level identifiers
 */
#define CTL_UNSPEC        0                /* unused */
#define CTL_KERN        1                /* "high kernel": proc, limits */
#define CTL_VM                2                /* virtual memory */
#define CTL_VFS                3                /* filesystem, mount type is next */
#define CTL_NET                4                /* network, see socket.h */
#define CTL_DEBUG        5                /* debugging parameters */
#define CTL_HW                6                /* generic cpu/io */
#define CTL_MACHDEP        7                /* machine dependent */
#define CTL_USER        8                /* user-level */
#define CTL_P1003_1B        9                /* POSIX 1003.1B */
#define CTL_MAXID        10                /* number of valid top-level ids */

/*
 * CTL_KERN identifiers
 */
#define KERN_OSTYPE             1        /* string: system version */
#define KERN_OSRELEASE          2        /* string: system release */
#define KERN_OSREV              3        /* int: system revision */
#define KERN_VERSION            4        /* string: compile time info */
#define KERN_MAXVNODES          5        /* int: max vnodes */
#define KERN_MAXPROC            6        /* int: max processes */
#define KERN_MAXFILES           7        /* int: max open files */
#define KERN_ARGMAX             8        /* int: max arguments to exec */
#define KERN_SECURELVL          9        /* int: system security level */
#define KERN_HOSTNAME           10        /* string: hostname */
#define KERN_HOSTID             11        /* int: host identifier */
#define KERN_CLOCKRATE          12        /* struct: struct clockrate */
#define KERN_VNODE              13        /* struct: vnode structures */
#define KERN_PROC               14        /* struct: process entries */
#define KERN_FILE               15        /* struct: file entries */
#define KERN_PROF               16        /* node: kernel profiling info */
#define KERN_POSIX1             17        /* int: POSIX.1 version */
#define KERN_NGROUPS            18        /* int: # of supplemental group ids */
#define KERN_JOB_CONTROL        19        /* int: is job control available */
#define KERN_SAVED_IDS          20        /* int: saved set-user/group-ID */
#define KERN_BOOTTIME           21        /* struct: time kernel was booted */
#define KERN_NISDOMAINNAME      22        /* string: YP domain name */
#define KERN_UPDATEINTERVAL     23        /* int: update process sleep time */
#define KERN_OSRELDATE          24        /* int: kernel release date */
#define KERN_NTP_PLL            25        /* node: NTP PLL control */
#define KERN_BOOTFILE           26        /* string: name of booted kernel */
#define KERN_MAXFILESPERPROC    27        /* int: max open files per proc */
#define KERN_MAXPROCPERUID      28        /* int: max processes per uid */
#define KERN_DUMPDEV            29        /* struct cdev *: device to dump on */
#define KERN_IPC                30        /* node: anything related to IPC */
#define KERN_DUMMY              31        /* unused */
#define KERN_PS_STRINGS         32        /* int: address of PS_STRINGS */
#define KERN_USRSTACK           33        /* int: address of USRSTACK */
#define KERN_LOGSIGEXIT         34        /* int: do we log sigexit procs? */
#define KERN_IOV_MAX            35        /* int: value of UIO_MAXIOV */
#define KERN_HOSTUUID           36        /* string: host UUID identifier */
#define KERN_ARND               37        /* int: from arc4rand() */
#define KERN_MAXID              38        /* number of valid kern ids */
/*
 * KERN_PROC subtypes
 */
#define        KERN_PROC_ALL                0        /* everything */
#define        KERN_PROC_PID                1        /* by process id */
#define        KERN_PROC_PGRP                2        /* by process group id */
#define        KERN_PROC_SESSION        3        /* by session of pid */
#define        KERN_PROC_TTY                4        /* by controlling tty */
#define        KERN_PROC_UID                5        /* by effective uid */
#define        KERN_PROC_RUID                6        /* by real uid */
#define        KERN_PROC_ARGS                7        /* get/set arguments/proctitle */
#define        KERN_PROC_PROC                8        /* only return procs */
#define        KERN_PROC_SV_NAME        9        /* get syscall vector name */
#define        KERN_PROC_RGID                10        /* by real group id */
#define        KERN_PROC_GID                11        /* by effective group id */
#define        KERN_PROC_PATHNAME        12        /* path to executable */
#define        KERN_PROC_OVMMAP        13        /* Old VM map entries for process */
#define        KERN_PROC_OFILEDESC        14        /* Old file descriptors for process */
#define        KERN_PROC_KSTACK        15        /* Kernel stacks for process */
#define        KERN_PROC_INC_THREAD        0x10        /*
                                         * modifier for pid, pgrp, tty,
                                         * uid, ruid, gid, rgid and proc
                                         * This effectively uses 16-31
                                         */
#define        KERN_PROC_VMMAP                32        /* VM map entries for process */
#define        KERN_PROC_FILEDESC        33        /* File descriptors for process */
#define        KERN_PROC_GROUPS        34      ne        KERN_PROC_ENV                35        /* get environment */
#define        KERN_PROC_AUXV                36        /* get ELF auxiliary vector */
#define        KERN_PROC_RLIMIT        37        /* process resource limits */
#define        KERN_PROC_PS_STRINGS        38        /* get ps_strings location */
#define        KERN_PROC_UMASK                39        /* process umask */
#define        KERN_PROC_OSREL                40        /* osreldate for process binary */
#define        KERN_PROC_SIGTRAMP        41        /* signal trampoline location */

/*
 * KERN_IPC identifiers
 */
#define        KIPC_MAXSOCKBUF                1        /* int: max size of a socket buffer */
#define        KIPC_SOCKBUF_WASTE        2        /* int: wastage factor in sockbuf */
#define        KIPC_SOMAXCONN                3        /* int: max length of connection q */
#define        KIPC_MAX_LINKHDR        4        /* int: max length of link header */
#define        KIPC_MAX_PROTOHDR        5        /* int: max length of network header */
#define        KIPC_MAX_HDR                6        /* int: max total length of headers */
#define        KIPC_MAX_DATALEN        7        /* int: max length of data? */

/*
 * CTL_HW identifiers
 */
#define        HW_MACHINE       1                /* string: machine class */
#define        HW_MODEL         2                /* string: specific machine model */
#define        HW_NCPU          3                /* int: number of cpus */
#define        HW_BYTEORDER     4                /* int: machine byte order */
#define        HW_PHYSMEM       5                /* int: total memory */
#define        HW_USERMEM       6                /* int: non-kernel memory */
#define        HW_PAGESIZE      7                /* int: software page size */
#define        HW_DISKNAMES     8                /* strings: disk drive names */
#define        HW_DISKSTATS     9                /* struct: diskstats[] */
#define        HW_FLOATINGPT    10                /* int: has HW floating point? */
#define        HW_MACHINE_ARCH  11                /* string: machine architecture */
#define        HW_REALMEM       12                /* int: 'real' memory */
#define        HW_MAXID         13                /* number of valid hw ids */

/*
 * CTL_USER definitions
 */
#define USER_CS_PATH            1   /* string: _CS_PATH */
#define USER_BC_BASE_MAX        2   /* int: BC_BASE_MAX */
#define USER_BC_DIM_MAX         3   /* int: BC_DIM_MAX */
#define USER_BC_SCALE_MAX       4   /* int: BC_SCALE_MAX */
#define USER_BC_STRING_MAX      5   /* int: BC_STRING_MAX */
#define USER_COLL_WEIGHTS_MAX   6   /* int: COLL_WEIGHTS_MAX */
#define USER_EXPR_NEST_MAX      7   /* int: EXPR_NEST_MAX */
#define USER_LINE_MAX           8   /* int: LINE_MAX */
#define USER_RE_DUP_MAX         9   /* int: RE_DUP_MAX */
#define USER_POSIX2_VERSION     10  /* int: POSIX2_VERSION */
#define USER_POSIX2_C_BIND      11  /* int: POSIX2_C_BIND */
#define USER_POSIX2_C_DEV       12  /* int: POSIX2_C_DEV */
#define USER_POSIX2_CHAR_TERM   13  /* int: POSIX2_CHAR_TERM */
#define USER_POSIX2_FORT_DEV    14  /* int: POSIX2_FORT_DEV */
#define USER_POSIX2_FORT_RUN    15  /* int: POSIX2_FORT_RUN */
#define USER_POSIX2_LOCALEDEF   16  /* int: POSIX2_LOCALEDEF */
#define USER_POSIX2_SW_DEV      17  /* int: POSIX2_SW_DEV */
#define USER_POSIX2_UPE         18  /* int: POSIX2_UPE */
#define USER_STREAM_MAX         19  /* int: POSIX2_STREAM_MAX */
#define USER_TZNAME_MAX         20  /* int: POSIX2_TZNAME_MAX */
#define USER_MAXID              21  /* number of valid user ids */

#ifdef KERNEL_INTERNAL

/*
 * Declare oids.
 */
extern struct sysctl_oid_list sysctl__children;
SYSCTL_DECL(_kern);

#else /* !KERNEL_INTERNAL */
int        sysctl(const int *, unsigned int, void *, size_t *, const void *, size_t);
int        sysctlbyname(const char *, void *, size_t *, const void *, size_t);
int        sysctlnametomib(const char *, int *, size_t *);
#endif /* KERNEL_INTERNAL */

#endif /* _SYS_SYSCTL_H_ */