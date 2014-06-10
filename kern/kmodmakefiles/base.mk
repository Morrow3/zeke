# Base system
base-SRC-1 += $(wildcard ./*.c)
base-SRC-$(configSCHED_TINY) += $(wildcard sched_tiny/*.c)

# Generic Data Structures
base-SRC-1 += $(wildcard generic/*.c)

# Kernel logging
base-SRC-$(configKLOGGER) += kerror/kerror.c
base-SRC-$(configKLOGGER) += kerror/kerror_buf.c
base-SRC-$(configKERROR_UART) += kerror/kerror_uart.c
base-SRC-$(configKERROR_FB) += kerror/kerror_fb.c

# Virtual file system
base-SRC-1 += $(wildcard fs/*.c)
# devfs
#base-SRC-1 += fs/dev/devfs.c
# ramfs
base-SRC-$(configRAMFS) += fs/ramfs/*.c

