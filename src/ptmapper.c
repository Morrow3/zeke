/**
 *******************************************************************************
 * @file    ptmapper.c
 * @author  Olli Vanhoja
 * @brief   Page table mapper.
 * @section LICENSE
 * Copyright (c) 2013, 2014 Olli Vanhoja <olli.vanhoja@cs.helsinki.fi>
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

#define KERNEL_INTERNAL
#include <kinit.h>
#include <kstring.h>
#include <kerror.h>
#include <generic/bitmap.h>
#include <sys/sysctl.h>
#include <ptmapper.h>

void ptmapper_init(void);
HW_PREINIT_ENTRY(ptmapper_init);

/* Fixed Page Tables */

/* Kernel master page table (L1) */
mmu_pagetable_t mmu_pagetable_master = {
    .vaddr          = 0,
    .pt_addr        = 0, /* These will be set */
    .master_pt_addr = 0, /* later in the init phase */
    .type           = MMU_PTT_MASTER,
    .dom            = MMU_DOM_KERNEL
};

mmu_pagetable_t mmu_pagetable_system = {
    .vaddr          = MMU_VADDR_KERNEL_START,
    .pt_addr        = 0,
    .master_pt_addr = 0,
    .type           = MMU_PTT_COARSE,
    .dom            = MMU_DOM_KERNEL
};

/* Fixed Regions */

/* TODO Temporarily mapped as one big area */
mmu_region_t mmu_region_kernel = {
    .vaddr          = MMU_VADDR_KERNEL_START,
    .num_pages      = MMU_PAGE_CNT_BY_RANGE(MMU_VADDR_KERNEL_START, \
                        MMU_VADDR_KERNEL_END, 4096),
    .ap             = MMU_AP_RWRW, /* TODO this must be changed later to RWNA */
    .control        = MMU_CTRL_MEMTYPE_WB,
    .paddr          = 0x0,
    .pt             = &mmu_pagetable_system
};

uintptr_t __text_shared_start __attribute__((weak));
uintptr_t __text_shared_end __attribute__((weak));
mmu_region_t mmu_region_shared = {
    .vaddr          = MMU_VADDR_SHARED_START,
    .num_pages      = MMU_PAGE_CNT_BY_RANGE(MMU_VADDR_SHARED_START, \
                        MMU_VADDR_SHARED_END, 4096),
    .ap             = MMU_AP_RWRO,
    .control        = MMU_CTRL_MEMTYPE_WT,
    .paddr          = 0, /* Will be set later. */
    .pt             = &mmu_pagetable_system
};

#define PTREGION_SIZE \
    MMU_PAGE_CNT_BY_RANGE(PTMAPPER_PT_START, PTMAPPER_PT_END, 1048576) /* MB */
mmu_region_t mmu_region_page_tables = {
    .vaddr          = PTMAPPER_PT_START,
    .num_pages      = PTREGION_SIZE,
    .ap             = MMU_AP_RWNA,
    .control        = MMU_CTRL_MEMTYPE_WT | MMU_CTRL_XN,
    .paddr          = PTMAPPER_PT_START,
    .pt             = &mmu_pagetable_master
};

/**
 * Coarse page tables per MB.
 * Number of page tables that can be stored in one MB.
 * @note MMU_PTSZ_MASTER is a multiple of MMU_PTSZ_COARSE.
 */
#define PTS_PER_MB ((1024 * 1024) / MMU_PTSZ_COARSE)

/**
 * Page table region allocation bitmap.
 */
uint32_t ptm_alloc_map[E2BITMAP_SIZE(PTREGION_SIZE * PTS_PER_MB)];
#undef PTS_PER_MB

static int ptm_nr_pt = 0;
SYSCTL_INT(_vm, OID_AUTO, ptm_nr_pt, CTLFLAG_RD, &ptm_nr_pt, 0,
    "Total number of page tables allocated.");

static size_t ptm_mem_free = PTREGION_SIZE * 1048576;
SYSCTL_UINT(_vm, OID_AUTO, ptm_mem_free, CTLFLAG_RD, &ptm_mem_free, 0,
    "Amount of free page table region memory.");

static const size_t ptm_mem_tot = PTREGION_SIZE * 1048576;
SYSCTL_UINT(_vm, OID_AUTO, ptm_mem_tot, CTLFLAG_RD,
    (unsigned int *)(&ptm_mem_tot), 0,
    "Total size of page table region.");

#define PTM_SIZEOF_MAP sizeof(ptm_alloc_map)
#define PTM_MASTER  0x10 /*!< Len of master page table in ptm_alloc_map. */
#define PTM_COARSE  0x01 /*!< Len of coarse page table in ptm_alloc_map. */

/**
 * Convert a block index to an address.
 */
#define PTM_BLOCK2ADDR(block) (PTMAPPER_PT_START + (block) * MMU_PTSZ_COARSE)

/**
 * Convert an address to a block index.
 */
#define PTM_ADDR2BLOCK(addr) (((addr) - PTMAPPER_PT_START) / MMU_PTSZ_COARSE)

/**
 * Allocate a free block in ptm_alloc_map.
 * @param retval[out]   Index of the first contiguous block of requested length.
 * @param len           Block size, either PTM_MASTER or PTM_COARSE.
 * @return Returns zero if a free block found; Value other than zero if there
 *         is no free contiguous block of requested length.
 */
#define PTM_ALLOC(retval, len) \
    bitmap_block_alloc(retval, len, ptm_alloc_map, PTM_SIZEOF_MAP)

/**
 * Free a block that has been previously allocated.
 * @param block is the block that has been allocated with PTM_ALLOC.
 * @param len   is the length of the block, either PTM_MASTER or PTM_COARSE.
 */
#define PTM_FREE(block, len) \
    bitmap_block_update(ptm_alloc_map, 0, block, len)


/**
 * Page table mapper init function.
 * @note This function should be called by mmu init.
 */
void ptmapper_init(void)
{
    SUBSYS_INIT();
    KERROR(KERROR_DEBUG, "ptmapper init");

    /* Allocate memory for mmu_pagetable_master */
    if (ptmapper_alloc(&mmu_pagetable_master)) {
        panic("Can't allocate memory for master page table.");
    }

    mmu_pagetable_system.master_pt_addr = mmu_pagetable_master.master_pt_addr;
    if (ptmapper_alloc(&mmu_pagetable_system)) {
        panic("Can't allocate memory for system page table.");
    }

    /* Initialize system page tables */
    mmu_init_pagetable(&mmu_pagetable_master);
    mmu_init_pagetable(&mmu_pagetable_system);

    /* Calculate physical address space of the shared region. */
    mmu_region_shared.paddr = __text_shared_start;
    mmu_region_shared.num_pages =
        MMU_PAGE_CNT_BY_RANGE(__text_shared_start, __text_shared_end, 4096);

    /* Fill page tables with translations & attributes */
    mmu_map_region(&mmu_region_kernel);
    mmu_map_region(&mmu_region_shared);
    mmu_map_region(&mmu_region_page_tables);

    /* Activate page tables */
    mmu_attach_pagetable(&mmu_pagetable_master); /* Load L1 TTB */
    KERROR(KERROR_DEBUG, "Attached TTB mmu_pagetable_master");
    mmu_attach_pagetable(&mmu_pagetable_system); /* Add L2 pte into L1 master pt */
    KERROR(KERROR_DEBUG, "Attached mmu_pagetable_system");
}

/**
 * Allocate memory for a page table.
 * Allocate memory for a page table from the page table region. This function
 * will not activate the page table or do anything besides updating necessary
 * varibles in pt and reserve a block of memory from the area.
 * @note master_pt_addr will be only set for a page table struct if allocated
 * page table is a master page table.
 * @param pt    is the page table struct without page table address pt_addr.
 * @return  Returns zero if succeed; Otherwise value other than zero indicating
 *          that the page table allocation has failed.
 */
int ptmapper_alloc(mmu_pagetable_t * pt)
{
    size_t block;
    size_t addr;
    size_t size = 0; /* Size in bitmap */
    size_t bsize = 0; /* Size in bytes */
    int retval = 0;

    switch (pt->type) {
        case MMU_PTT_MASTER:
            size = PTM_MASTER;
            bsize = MMU_PTSZ_MASTER;
            break;
        case MMU_PTT_COARSE:
            size = PTM_COARSE;
            bsize = MMU_PTSZ_COARSE;
            break;
        default:
            break;
    }

    /* Try to allocate a new page table */
    if ((size == 0) ? 0 : !PTM_ALLOC(&block, size)) {
#if configDEBUG != 0
        char buf[80];
#endif

        addr = PTM_BLOCK2ADDR(block);
#if configDEBUG != 0
        ksprintf(buf, sizeof(buf), "Page table allocated @ %x of size %u bytes", addr, bsize);
        KERROR(KERROR_DEBUG, buf);
#endif
        pt->pt_addr = addr;
        if (pt->type == MMU_PTT_MASTER) {
            pt->master_pt_addr = addr;
        }

        /* Accounting for sysctl */
        ptm_nr_pt++;
        ptm_mem_free -= bsize;
    } else {
        KERROR(KERROR_ERR, "Out of page memory");
        retval = -1;
    }

    return retval;
}

/**
 * Free page table.
 * Frees a page table that has been previously allocated with ptmapper_alloc.
 * @note    Page table pt should be detached properly before calling this
 *          function and it is usually good idea to unmap any regions still
 *          mapped with the page table before removing it completely.
 * @param pt is the page table to be freed.
 */
void ptmapper_free(mmu_pagetable_t * pt)
{
    size_t block;
    size_t size = 0; /* Size in bitmap */
    size_t bsize = 0; /* Size in bytes */

    switch (pt->type) {
        case MMU_PTT_MASTER:
            size = PTM_MASTER;
            bsize = MMU_PTSZ_MASTER;
            break;
        case MMU_PTT_COARSE:
            size = PTM_COARSE;
            bsize = MMU_PTSZ_COARSE;
            break;
        default:
            KERROR(KERROR_ERR, "Attemp to free an invalid page table.");
            return;
    }

    block = PTM_ADDR2BLOCK(pt->pt_addr);
    PTM_FREE(block, size);

    /* Accounting for sysctl */
    ptm_nr_pt--;
    ptm_mem_free += bsize;

}
