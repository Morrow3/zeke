/**
 * @file    msdosfs_denode.c
 * @author  Olli Vanhoja
 * @brief   MSDOSFS
 * @section LICENSE
 * Copyright (C) 2014 Olli Vanhoja <olli.vanhoja@cs.helsinki.fi>
 * Copyright (C) 1994, 1995, 1997 Wolfgang Solfrank.
 * Copyright (C) 1994, 1995, 1997 TooLs GmbH.
 * All rights reserved.
 * Original code by Paul Popelka (paulp@uts.amdahl.com) (see below).
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *  This product includes software developed by TooLs GmbH.
 * 4. The name of TooLs GmbH may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY TOOLS GMBH ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL TOOLS GMBH BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * Written by Paul Popelka (paulp@uts.amdahl.com)
 *
 * You can do anything you want with this software, just don't say you wrote
 * it, and don't remove this notice.
 *
 * This software is provided "as is".
 *
 * The author supplies this software to be publicly redistributed on the
 * understanding that the author is not responsible for the correct
 * functioning of this software in any circumstances and is not liable for
 * any damages caused by this software.
 *
 * October 1992
 */

#define KERNEL_INTERNAL 1
#include <sys/param.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <mount.h>
#include <kstring.h>
#include <kerror.h>
#include <buf.h>
#include <kmalloc.h>
#include <fs/vfs_hash.h>
#include <fs/fs.h>
#include <vm/vm.h>
#include "bpb.h"
#include "direntry.h"
#include "denode.h"
#include "fat.h"
#include "msdosfsmount.h"

#if configVFS_HASH == 0
#error configMSDOSFS requires configVFS_HASH
#endif

static int
de_vncmpf(struct vnode * vp, void * arg)
{
    const struct denode * const de = VTODE(vp);
    const uint64_t * const a = arg;

    return (de->de_inode != *a);
}

/*
 * If deget() succeeds it returns with the gotten denode locked().
 *
 * pmp       - address of msdosfsmount structure of the filesystem containing
 *         the denode of interest.  The address of
 *         the msdosfsmount structure are used.
 * dirclust  - which cluster bp contains, if dirclust is 0 (root directory)
 *         diroffset is relative to the beginning of the root directory,
 *         otherwise it is cluster relative.
 * diroffset - offset past begin of cluster of denode we want
 * depp      - returns the address of the gotten denode.
 */
int
deget(pmp, dirclust, diroffset, depp)
    struct msdosfsmount *pmp;   /* so we know the maj/min number */
    unsigned long dirclust;     /* cluster this dir entry came from */
    unsigned long diroffset;    /* index of entry within the cluster */
    struct denode **depp;       /* returns the addr of the gotten denode */
{
    int error;
    uint64_t inode;
    struct fs_superblock * mntp = pmp->pm_mountp;
    struct direntry *direntptr;
    struct denode *ldep;
    struct vnode *nvp, *xvp;
    struct buf *bp;
#ifdef configMSDOSFS_DEBUG
    char msgbuf[80];
#endif

#ifdef configMSDOSFS_DEBUG
    ksprintf(msgbuf, sizeof(msgbuf),
             "deget(pmp %p, dirclust %lu, diroffset %lx, depp %p)\n",
             pmp, dirclust, diroffset, depp);
    KERROR(KERROR_DEBUG, msgbuf);
#endif

    /*
     * On FAT32 filesystems, root is a (more or less) normal
     * directory
     */
    if (FAT32(pmp) && dirclust == MSDOSFSROOT)
        dirclust = pmp->pm_rootdirblk;

    /*
     * See if the denode is in the denode cache. Use the location of
     * the directory entry to compute the hash value. For subdir use
     * address of "." entry. For root dir (if not FAT32) use cluster
     * MSDOSFSROOT, offset MSDOSFSROOT_OFS
     *
     * NOTE: The check for de_refcnt > 0 below insures the denode being
     * examined does not represent an unlinked but still open file.
     * These files are not to be accessible even when the directory
     * entry that represented the file happens to be reused while the
     * deleted file is still open.
     */
    inode = (uint64_t)pmp->pm_bpcluster * dirclust + diroffset;

    error = vfs_hash_get(mntp, inode, &nvp, de_vncmpf, &inode);
    if (error)
        return error;
    if (nvp != NULL) {
        *depp = VTODE(nvp);
        KASSERT((*depp)->de_dirclust == dirclust, ("wrong dirclust"));
        KASSERT((*depp)->de_diroffset == diroffset, ("wrong diroffset"));
        return 0;
    }

#if 0
    ldep = kmalloc(sizeof(struct denode), M_MSDOSFSNODE, M_WAITOK | M_ZERO);
#endif
    ldep = kmalloc(sizeof(struct denode));

    /*
     * Directory entry was not in cache, have to create a vnode and
     * copy it from the passed disk buffer.
     */
    fs_vnode_init(&ldep->de_vnode, inode, mntp, &msdosfs_vnode_ops);

    if (error) {
        *depp = NULL;
        kfree(ldep);
        return error;
    }
    ldep->de_flag = 0;
    ldep->de_dirclust = dirclust;
    ldep->de_diroffset = diroffset;
    ldep->de_inode = inode;
    VN_LOCK(nvp);
    fc_purge(ldep, 0);  /* init the fat cache for this denode */
    error = vfs_hash_insert(nvp, inode, &xvp, de_vncmpf, &inode);
    if (error) {
        *depp = NULL;
        return error;
    }
    if (xvp != NULL) {
        *depp = VTODE(xvp);
        return 0;
    }

    ldep->de_pmp = pmp;
    ldep->de_refcnt = 1;
    /*
     * Copy the directory entry into the denode area of the vnode.
     */
    if ((dirclust == MSDOSFSROOT
         || (FAT32(pmp) && dirclust == pmp->pm_rootdirblk))
        && diroffset == MSDOSFSROOT_OFS) {
        /*
         * Directory entry for the root directory. There isn't one,
         * so we manufacture one. We should probably rummage
         * through the root directory and find a label entry (if it
         * exists), and then use the time and date from that entry
         * as the time and date for the root denode.
         */

        ldep->de_Attributes = ATTR_DIRECTORY;
        ldep->de_LowerCase = 0;
        if (FAT32(pmp))
            ldep->de_StartCluster = pmp->pm_rootdirblk;
            /* de_FileSize will be filled in further down */
        else {
            ldep->de_StartCluster = MSDOSFSROOT;
            ldep->de_FileSize = pmp->pm_rootdirsize * MSDOSFS_BSIZE;
        }
        /*
         * fill in time and date so that fattime2timespec() doesn't
         * spit up when called from msdosfs_getattr() with root
         * denode
         */
        ldep->de_CHun = 0;
        ldep->de_CTime = 0x0000;    /* 00:00:00  */
        ldep->de_CDate = (0 << DD_YEAR_SHIFT) | (1 << DD_MONTH_SHIFT)
            | (1 << DD_DAY_SHIFT);
        /* Jan 1, 1980   */
        ldep->de_ADate = ldep->de_CDate;
        ldep->de_MTime = ldep->de_CTime;
        ldep->de_MDate = ldep->de_CDate;
        /* leave the other fields as garbage */
    } else {
        error = readep(pmp, dirclust, diroffset, &bp, &direntptr);
        if (error) {
            /*
             * The denode does not contain anything useful, so
             * it would be wrong to leave it on its hash chain.
             * Arrange for vput() to just forget about it.
             */
            ldep->de_Name[0] = SLOT_DELETED;

            VN_UNLOCK(nvp);
            *depp = NULL;
            return error;
        }
        (void)DE_INTERNALIZE(ldep, direntptr);
        brelse(bp);
    }

    /*
     * Fill in a few fields of the vnode and finish filling in the
     * denode.  Then return the address of the found denode.
     */
    if (ldep->de_Attributes & ATTR_DIRECTORY) {
        /*
         * Since DOS directory entries that describe directories
         * have 0 in the filesize field, we take this opportunity
         * to find out the length of the directory and plug it into
         * the denode structure.
         */
        unsigned long size;

        /*
         * XXX it sometimes happens that the "." entry has cluster
         * number 0 when it shouldn't.  Use the actual cluster number
         * instead of what is written in directory entry.
         */
        if (diroffset == 0 && ldep->de_StartCluster != dirclust) {
#ifdef configMSDOSFS_DEBUG
            ksprintf(msgbuf, sizeof(msgbuf),
                     "deget(): \".\" entry at clust %lu != %lu\n",
                     dirclust, ldep->de_StartCluster);
            KERROR(KERROR_DEBUG, msgbuf);
#endif
            ldep->de_StartCluster = dirclust;
        }

        nvp->vn_mode = S_IFDIR;
        if (ldep->de_StartCluster != MSDOSFSROOT) {
            error = pcbmap(ldep, 0xffff, 0, &size, 0);
            if (error == E2BIG) {
                ldep->de_FileSize = de_cn2off(pmp, size);
                error = 0;
            } else {
#ifdef configMSDOSFS_DEBUG
                ksprintf(msgbuf, sizeof(msgbuf),
                         "deget(): pcbmap returned %d\n", error);
                KERROR(KERROR_DEBUG, msgbuf);
#endif
            }
        }
    } else {
        nvp->vn_mode = S_IFREG;
    }
    *depp = ldep;
    return 0;
}

int
deupdat(dep, waitfor)
    struct denode *dep;
    int waitfor;
{
    struct direntry dir;
    struct timespec ts;
    struct buf *bp;
    struct direntry *dirp;
    int error;

    if (DETOV(dep)->sb->mode_flags & MNT_RDONLY) {
        dep->de_flag &= ~(DE_UPDATE | DE_CREATE | DE_ACCESS |
            DE_MODIFIED);
        return 0;
    }
    getnanotime(&ts);
    DETIMES(dep, &ts, &ts, &ts);
    if ((dep->de_flag & DE_MODIFIED) == 0 && waitfor == 0)
        return 0;
    dep->de_flag &= ~DE_MODIFIED;
    if (VN_IS_FSROOT(DETOV(dep)))
        return -EINVAL;
    if (dep->de_refcnt <= 0)
        return 0;
    error = readde(dep, &bp, &dirp);
    if (error)
        return error;
    DE_EXTERNALIZE(&dir, dep);
    if (memcmp(dirp, &dir, sizeof(dir)) == 0) {
        if (waitfor == 0 || (bp->b_flags & B_DELWRI) == 0) {
            brelse(bp);
            return 0;
        }
    } else
        *dirp = dir;
    if (waitfor)
        error = bwrite(bp);
#if 0 /* TODO */
    else if (vm_page_count_severe() || buf_dirty_count_severe())
        bawrite(bp);
#endif
    else
        bdwrite(bp);
    return error;
}

/*
 * Truncate the file described by dep to the length specified by length.
 */
int
detrunc(dep, length, flags)
    struct denode *dep;
    unsigned long length;
    int flags;
{
    int error;
    int allerror;
    unsigned long eofentry;
    unsigned long chaintofree;
    off_t bn;
    int boff;
    int isadir = dep->de_Attributes & ATTR_DIRECTORY;
    struct buf *bp;
    struct msdosfsmount *pmp = dep->de_pmp;
#ifdef configMSDOSFS_DEBUG
    char msgbuf[80];
#endif

#ifdef configMSDOSFS_DEBUG
    ksprintf(msgbuf, sizeof(msgbuf),
             "detrunc(): file %s, length %lu, flags %x\n",
             dep->de_Name, length, flags);
    KERROR(KERROR_DEBUG, msgbuf);
#endif

    /*
     * Disallow attempts to truncate the root directory since it is of
     * fixed size.  That's just the way dos filesystems are.  We use
     * the VROOT bit in the vnode because checking for the directory
     * bit and a startcluster of 0 in the denode is not adequate to
     * recognize the root directory at this point in a file or
     * directory's life.
     */
    if (VN_IS_FSROOT(DETOV(dep)) && !FAT32(pmp)) {
#ifdef configMSDOSFS_DEBUG
        ksprintf(msgbuf, sizeof(msgbuf),
            "detrunc(): can't truncate root directory, clust %ld, offset %ld\n",
             dep->de_dirclust, dep->de_diroffset);
        KERROR(KERROR_DEBUG, msgbuf);
#endif
        return -EINVAL;
    }

    if (dep->de_FileSize < length) {
        vnode_pager_setsize(DETOV(dep), length);
        return deextend(dep, length);
    }

    /*
     * If the desired length is 0 then remember the starting cluster of
     * the file and set the StartCluster field in the directory entry
     * to 0.  If the desired length is not zero, then get the number of
     * the last cluster in the shortened file.  Then get the number of
     * the first cluster in the part of the file that is to be freed.
     * Then set the next cluster pointer in the last cluster of the
     * file to CLUST_EOFE.
     */
    if (length == 0) {
        chaintofree = dep->de_StartCluster;
        dep->de_StartCluster = 0;
        eofentry = ~0;
    } else {
        error = pcbmap(dep, de_clcount(pmp, length) - 1, 0,
                   &eofentry, 0);
        if (error) {
#ifdef configMSDOSFS_DEBUG
            ksprintf(msgbuf, sizeof(msgbuf),
                     "detrunc(): pcbmap fails %d\n", error);
            KERROR(KERROR_DEBUG, msgbuf);
#endif
            return error;
        }
    }

    fc_purge(dep, de_clcount(pmp, length));

    /*
     * If the new length is not a multiple of the cluster size then we
     * must zero the tail end of the new last cluster in case it
     * becomes part of the file again because of a seek.
     */
    if ((boff = length & pmp->pm_crbomask) != 0) {
        if (isadir) {
            bn = cntobn(pmp, eofentry);
            error = bread(pmp->pm_devvp, bn, pmp->pm_bpcluster, &bp);
            if (error) {
                brelse(bp);
#ifdef configMSDOSFS_DEBUG
                ksprintf(msgbuf, sizeof(msgbuf), "detrunc(): bread fails %d\n",
                         error);
                KERROR(KERROR_DEBUG, msgbuf);
#endif
                return error;
            }
            memset((void *)(bp->b_data + boff), '\0', pmp->pm_bpcluster - boff);
            /* TODO */
#if 0
            if (flags & IO_SYNC) {
#endif
                bwrite(bp);
#if 0
            } else {
                bdwrite(bp);
            }
#endif
        }
    }

    /*
     * Write out the updated directory entry.  Even if the update fails
     * we free the trailing clusters.
     */
    dep->de_FileSize = length;
    if (!isadir)
        dep->de_flag |= DE_UPDATE | DE_MODIFIED;
    allerror = vtruncbuf(DETOV(dep), length, pmp->pm_bpcluster);
#ifdef configMSDOSFS_DEBUG
    if (allerror) {
        ksprintf(msgbuf, sizeof(msgbuf), "detrunc(): vtruncbuf error %d\n",
                 allerror);
        KERROR(KERROR_DEBUG, msgbuf);
    }
#endif
    error = deupdat(dep, !DOINGASYNC((DETOV(dep))));
    if (error != 0 && allerror == 0) {
        allerror = error;
#ifdef configMSDOSFS_DEBUG
        ksprintf(msgbuf, sizeof(msgbuf),
                 "detrunc(): allerror %d, eofentry %lu\n",
                 allerror, eofentry);
        KERROR(KERROR_DEBUG, msgbuf);
#endif
    }

    /*
     * If we need to break the cluster chain for the file then do it
     * now.
     */
    if (eofentry != ~0) {
        error = fatentry(FAT_GET_AND_SET, pmp, eofentry,
                 &chaintofree, CLUST_EOFE);
        if (error) {
#ifdef configMSDOSFS_DEBUG
            ksprintf(msgbuf, sizeof(msgbuf), "detrunc(): fatentry errors %d\n",
                     error);
            KERROR(KERROR_DEBUG, msgbuf);
#endif
            return error;
        }
        fc_setcache(dep, FC_LASTFC, de_cluster(pmp, length - 1),
                eofentry);
    }

    /*
     * Now free the clusters removed from the file because of the
     * truncation.
     */
    if (chaintofree != 0 && !MSDOSFSEOF(pmp, chaintofree))
        freeclusterchain(pmp, chaintofree);

    return allerror;
}

/*
 * Extend the file described by dep to length specified by length.
 */
int
deextend(struct denode * dep, unsigned long length)
{
    struct msdosfsmount *pmp = dep->de_pmp;
    unsigned long count;
    int error;

    /*
     * The root of a DOS filesystem cannot be extended.
     */
    if (VN_IS_FSROOT(DETOV(dep)) && !FAT32(pmp))
        return -EINVAL;

    /*
     * Directories cannot be extended.
     */
    if (dep->de_Attributes & ATTR_DIRECTORY)
        return -EISDIR;

    if (length <= dep->de_FileSize)
        panic("deextend: file too large");

    /*
     * Compute the number of clusters to allocate.
     */
    count = de_clcount(pmp, length) - de_clcount(pmp, dep->de_FileSize);
    if (count > 0) {
        if (count > pmp->pm_freeclustercount)
            return ENOSPC;
        error = extendfile(dep, count, NULL, NULL, DE_CLEAR);
        if (error) {
            /* truncate the added clusters away again */
            (void) detrunc(dep, dep->de_FileSize, 0);
            return error;
        }
    }
    dep->de_FileSize = length;
    dep->de_flag |= DE_UPDATE | DE_MODIFIED;
    return deupdat(dep, !DOINGASYNC(DETOV(dep)));
}

/*
 * Move a denode to its correct hash queue after the file it represents has
 * been moved to a new directory.
 */
void
reinsert(struct denode * dep)
{
    struct vnode *vp;

    /*
     * Fix up the denode cache.  If the denode is for a directory,
     * there is nothing to do since the hash is based on the starting
     * cluster of the directory file and that hasn't changed.  If for a
     * file the hash is based on the location of the directory entry,
     * so we must remove it from the cache and re-enter it with the
     * hash based on the new location of the directory entry.
     */
#if 0
    if (dep->de_Attributes & ATTR_DIRECTORY)
        return;
#endif
    vp = DETOV(dep);
    dep->de_inode = (uint64_t)dep->de_pmp->pm_bpcluster * dep->de_dirclust +
        dep->de_diroffset;
    vfs_hash_rehash(vp, dep->de_inode);
}

int msdosfs_reclaim(struct vnode * vp)
{
    struct denode *dep = VTODE(vp);
#ifdef configMSDOSFS_DEBUG
    char msgbuf[80];

    ksprintf(msgbuf, sizeof(msgbuf),
             "msdosfs_reclaim(): dep %p, file %s, refcnt %ld\n",
             dep, dep->de_Name, dep->de_refcnt);
    KERROR(KERROR_DEBUG, msgbuf);
#endif

    /*
     * Destroy the vm object and flush associated pages.
     */
    vnode_destroy_vobject(vp);
    /*
     * Remove the denode from its hash chain.
     */
    vfs_hash_remove(vp);
    /*
     * Purge old data structures associated with the denode.
     */
#if 0 /* XXX */
    dep->de_flag = 0;
#endif
    kfree(dep);

    return 0;
}

int
msdosfs_inactive(struct vnode * vp)
{
    struct denode *dep = VTODE(vp);
    int error = 0;
#ifdef configMSDOSFS_DEBUG
    char msgbuf[80];

    ksprintf(msgbuf, sizeof(msgbuf),
             "msdosfs_inactive(): dep %p, de_Name[0] %x\n",
             dep, dep->de_Name[0]);
    KERROR(KERROR_DEBUG, msgbuf);
#endif

    /*
     * Ignore denodes related to stale file handles.
     */
    if (dep->de_Name[0] == SLOT_DELETED || dep->de_Name[0] == SLOT_EMPTY)
        goto out;

    /*
     * If the file has been deleted and it is on a read/write
     * filesystem, then truncate the file, and mark the directory slot
     * as empty.  (This may not be necessary for the dos filesystem.)
     */
#ifdef configMSDOSFS_DEBUG
    ksprintf(msgbuf, sizeof(msgbuf),
             "msdosfs_inactive(): dep %p, refcnt %ld, mntflag %x, MNT_RDONLY %x\n",
             dep, dep->de_refcnt, vp->sb->mode_flags, MNT_RDONLY);
    KERROR(KERROR_DEBUG, msgbuf);
#endif
    if (dep->de_refcnt <= 0 && (vp->sb->mode_flags & MNT_RDONLY) == 0) {
        error = detrunc(dep, (unsigned long) 0, 0);
        dep->de_flag |= DE_UPDATE;
        dep->de_Name[0] = SLOT_DELETED;
    }
    deupdat(dep, 0);

out:
    /*
     * If we are done with the denode, reclaim it
     * so that it can be reused immediately.
     */
#ifdef configMSDOSFS_DEBUG
    ksprintf(msgbuf, sizeof(msgbuf),
             "msdosfs_inactive(): vn_refcount %d, de_Name[0] %x\n",
             vrefcnt(vp), dep->de_Name[0]);
    KERROR(KERROR_DEBUG, msgbuf);
#endif
    if (dep->de_Name[0] == SLOT_DELETED || dep->de_Name[0] == SLOT_EMPTY)
        vrecycle(vp);
    return error;
}
