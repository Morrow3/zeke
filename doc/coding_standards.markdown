Zeke Coding Standards & Generic Documentation
=============================================

Here is some misc documentation and generic guidelines on how to write code for
Zeke.

Directory Structure
-------------------

+ src/                  Most of the kernel code.
+ src/generic/          Generic data structures.
+ src/libkern/          Kernel "standard" library.
+ src/libkern/kstring/  String functions.
+ src/hal/              Harware abstraction layer.
+ src/fs/               Virtual file system abstraction and other file systems.
+ src/sched_X/          Thread scheduler implementations.
+ src/test/             Kernel space unit tests.
+ src/kunit/            In-kernel unit test framework.
+ include/              User space library headers.
+ lib/                  C runtime libraries and user space libraries.
+ config/               Kernel build config.
+ modmakefiles/         Kernel module makefiles.
+ sbin/                 System utilities.
+ tools/                Build tools/scripts.
+ test/                 User space unit tests.
+ test/punit/           User space unt test framework.


Naming Conventions
------------------

### File names

+ `module.c|h`  Any module that implements some functionality
+ `kmodule.c|h` Kernel scope source module that provides some external
                sycallable functionality
+ `lowlevel.S`  Assembly source code; Note that capital S for user files as file
                names ending with small s are reserved for compilation time
                files
+ `dev/`        Dev subsys modules
+ `thscope/`    Functions that are called and excecuted in thread scope;
                This means mainly syscall wrappers

*Warning:* Assembly sources with small suffix (.s) might be removed by
`make clean` as those are considered as automatically generated files.

### Global variables

There should not be need for any global variables but since you'll be still
declaring global variable please atleast use descriptive names.

There has been both naming conventions used mixed case with underline between
module name and rest of the name and everyting writen small with underlines.
Third conventions is some very ugly that was inherited from CMSIS which we are
now trying to get rid of.

Following names are somewhat acceptable:

+ `module_feature_name`

*Note:* `module_featureName` is obsoleted.

### Function names

+ `module_comp_function` + module = name that also appears in filename
                        + comp   = component/functionality eg. thread
                                   components will change thread status

*Note:* `module_compFunction` is obsoleted.


Standard Data Types
-------------------

### Typedefs

Typedefs are used in zeke for most of the structs and for some portability
related things where we may want or have to change types for example between
platforms.

### Enums

Avoid using enums in kernel space, they are ugly and don't behave nicely.
Usually enums even seems to generate more code than using #defined values.

Enums might be ok in user space and in interfaces between user space and
kernel space. Some standard things may even require using enums.


ABI and Calling Convention
--------------------------

Zeke uses, naturally, mainly the default calling convention defined by GCC and
Clang, which is a bit different than the standard calling convention. Here is
a brief description of ABI and calling convention used in Zeke.

    +----------+------+-----------------------------------------------------+
    | Register | Alt. | Usage                                               |
    +----------+------+-----------------------------------------------------+
    | r0       |      | First function arg./Return value for sizeof(size_t) |
    |          |      | return values.                                      |
    | r1       |      | Second function argument.                           |
    | r2       |      | Third function argument.                            |
    | r3       |      | Fourth function argument.                           |
    | r4       |      | Local variable. (non stacked scratch for syscalls)  |
    | r5 - r8  |      | Local variables.                                    |
    | r9       | rfp  | Local variable/Real frame pointer?                  |
    | r10      | sl   | Stack limit?                                        |
    | r11      |      | Argument pointer.                                   |
    | r12      | ip   | Temporary workspace?                                |
    | r13      | sp   | Stack pointer.                                      |
    | r14      | lr   | Link register.                                      |
    | r15      | pc   | Program counter.                                    |
    +----------+------+-----------------------------------------------------+

Table partially based on:
http://en.wikipedia.org/wiki/Calling_convention
http://www.ethernut.de/en/documents/arm-inline-asm.html

If return value is a pointer or otherwise too large to be returned by pointer
stored in r0.

Stack is always full-descending.


Kernel Initialization 
---------------------

Kernel initialization order is defined as follows:

For Cortex-M:
+ `SystemInit` - the clock system intitialization and other mandatory hw inits
+ `__libc_init_array` - Static constructors
+ `kinit` - Kernel initialization and load user code

For ARM11:
+ `hw_preinit`
+ `constructors`
+ `hw_postinit`
+ `kinit`

After kinit scheduler will kick in and initialization continues in a special
init thread.

Every initializer function should contain `SUBSYS_INIT("XXXX init");` as a first
line of the function and optionally `SUBSYS_DEP(YYYY_init);` lines declaring
subsystem initialization dependencies.

### Kernel module initializers

There is four kind of initializers supported at the moment:

+ *hw_preinit* for mainly hardware related initializers
+ *hw_postinit* for hardware related initializers
+ *constructor* (or init) for generic initialization

Optional kernel modules may use C static constructors and destructors to
generate init and fini code that will be run before any user code is loaded.
Constructors are also the preferred method to attach module with the kernel.

Currently there is no support for module unloading and any fini functions will
not be called in any case. Still decalaring destructors doesn't generate
compilation error and array of fini functions is still generated and might be
supported in the future.

Following example shows constructor/intializer notation supported by Zeke:

    void begin(void) __attribute__((constructor));
    void end(void) __attribute__((destructor));

    void begin(void)
    { ... }

    void end(void)
    { ... }

Constructor prioritizing is not supported for constructor pointers but however
linker uses SORT, which may or may not work as expected.

### hw_preinit and hw_postinit

hw_preinit and hw_postinit can be used by including kinit.h header file and
using following notation:

    HW_PREINIT_ENTRY(init1);
    HW_POSTINIT_ENTRY(init2);


Makefiles
---------

The main Makefile is responsible of parsing module makefiles and compiling the
whole kernel. Module makefiles are named as `<module>.mk` and are located in the
`modmakefiles` directory under the root.

Note that in context of Zeke there is two kinds of modules, the core/top level
subsystems that are packed as static library files and then there is kind of
submodules (often referred as modules too) that are optional compilation units
or compilation unit groups. Both are configured in the kernel configuration.

Module makefiles are parsed like normal makefiles but care should be taken when
changing global variables in these makefiles. Module makefiles are mainly
allowed to only append IDIR variable and all other variables should be more or
less specific to the module makefile itself and should begin with the name of
the module.

Example of a module makefile (test.mk):

    # Test module
    # Mandatory file
    # If any source files are declared like this the whole module becomes
    # mandatory and won't be dropped even if its configuration is set to zero.
    test-SRC-1 += src/test/test.c
    # Optional file
    # If all files are declared like this then the module is optional and can be
    # enabled or disabled in the `config.mk`.
    test-SRC-$(configTEST_CONFIGURABLE) += src/test/source.c
    # Assembly file
    test-ASRC$(configTEST_CONFIGURABLE) += src/test/lowlevel.S

The main makefile will automatically discover `test-SRC-1` list and will compile
a new static library based on the compilation units in the list. Name of the
library is derived from the makefile's name and so should be the first word of
the source file list name.

### Target specific compilation options and special files

As we don't want to put anything target specific and possibly changing data to
the main makefile we are using another makefile called `target.mak`. This file
contains the targer specific compilation options for different phases of
compilation. `target.mak` doesn't need to be changed if Zeke is compiled for a
different platform but it has to be updated if support for a new platform is to
be implemented.

`target.mak` should define at least following target specific variables:
+ `ASFLAGS`:    Containing CPU architecture flags
+ `MEMMAP`:     Specifying linker script for kernel image memory map
+ `STARTUP`:    Specifying target specific startup assembly source code file
+ `CRT`:        Specifying CRT library used with the target

and optionally:
+ `LLCFLAGS`: containing any target specific flags