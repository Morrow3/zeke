/**
 * @file    msdosfs_vnops.c
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
#include <buf.h>
#include <dirent.h>
#include <kerror.h>
#include <kstring.h>
#include <kmalloc.h>
#include <fs/fs.h>
#include <fs/devfs.h>
#include <mount.h>
#include <proc.h>
#include <sys/priv.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vm/vm.h>
#include "bpb.h"
#include "direntry.h"
#include "denode.h"
#include "fat.h"
#include "msdosfsmount.h"

#define DOS_FILESIZE_MAX    0xffffffff

/*
 * Some general notes:
 *
 * In the ufs filesystem the inodes, superblocks, and indirect blocks are
 * read/written using the vnode for the filesystem. Blocks that represent
 * the contents of a file are read/written using the vnode for the file
 * (including directories when they are read/written as files). This
 * presents problems for the dos filesystem because data that should be in
 * an inode (if dos had them) resides in the directory itself.  Since we
 * must update directory entries without the benefit of having the vnode
 * for the directory we must use the vnode for the filesystem.  This means
 * that when a directory is actually read/written (via read, write, or
 * readdir, or seek) we must use the vnode for the filesystem instead of
 * the vnode for the directory as would happen in ufs. This is to insure we
 * retreive the correct block from the buffer cache since the hash value is
 * based upon the vnode address and the desired block number.
 */

/*
 * Create a regular file. On entry the directory to contain the file being
 * created is locked.  We must release before we return. We must also free
 * the pathname buffer pointed at by cnp->cn_pnbuf, always on error, or
 * only if the SAVESTART bit in cn_flags is clear on success.
 */
static int
msdosfs_create(struct vnode * dvp, struct vnode ** vpp,
               const char * name, size_t name_len, struct stat * vap)
{
    struct denode ndirent;
    struct denode *dep;
    struct denode *pdep = VTODE(dvp);
    struct timespec ts;
    int error;
#ifdef configMSDOSFS_DEBUG
    char msgbuf[80];

    ksprintf(msgbuf, sizeof(msgbuf), "msdosfs_create(name %s, vap %p)\n",
           name, vap);
    KERROR(KERROR_DEBUG, msgbuf);

    if (!name)
        panic("msdosfs_create(): no name");
#endif

    /*
     * If this is the root directory and there is no space left we
     * can't do anything.  This is because the root directory can not
     * change size.
     */
    if (pdep->de_StartCluster == MSDOSFSROOT
        && pdep->de_fndoffset >= pdep->de_FileSize) {
        error = -ENOSPC;
        goto bad;
    }

    /*
     * Create a directory entry for the file, then call createde() to
     * have it installed. NOTE: DOS files are always executable.  We
     * use the absence of the owner write bit to make the file
     * readonly.
     */
    memset(&ndirent, '\0', sizeof(ndirent));
    error = uniqdosname(pdep, name, name_len, ndirent.de_Name);
    if (error)
        goto bad;

    ndirent.de_Attributes = ATTR_ARCHIVE;
    ndirent.de_LowerCase = 0;
    ndirent.de_StartCluster = 0;
    ndirent.de_FileSize = 0;
    ndirent.de_pmp = pdep->de_pmp;
    ndirent.de_flag = DE_ACCESS | DE_CREATE | DE_UPDATE;
    getnanotime(&ts);
    DETIMES(&ndirent, &ts, &ts, &ts);
    error = createde(&ndirent, pdep, &dep, name, name_len);
    if (error)
        goto bad;
    *vpp = DETOV(dep);

    return 0;

bad:
    return error;
}

static int
msdosfs_mknod(struct vnode * dvp, struct vnode ** vpp,
              const char * name, size_t name_len, struct stat * vap)
{
    return -EINVAL;
}

static int
msdosfs_open(struct vnode * vp, int mode, struct proc_info * proc,
             struct file * fp)
{
    struct denode * dep = VTODE(vp);
    vnode_create_vobject(vp, dep->de_FileSize, proc);

    return 0;
}

static int
msdosfs_close(struct vnode * vp, int fflag, struct proc_info * proc)
{
    struct denode * dep = VTODE(vp);
    struct timespec ts;

    VN_LOCK(vp);
    if (vp->vn_refcount > 1) {
        getnanotime(&ts);
        DETIMES(dep, &ts, &ts, &ts);
    }
    VN_UNLOCK(vp);

    return 0;
}

/* TODO NOT USED, REMOVE */
# if 0
static int msdosfs_access(struct vnode * vp, accmode_t accmode,
        struct proc_info * proc)
{
    struct denode * dep = VTODE(vp);
    struct msdosfsmount * pmp = dep->de_pmp;
    mode_t file_mode;

    file_mode = S_IRWXU|S_IRWXG|S_IRWXO;
    file_mode &= (S_ISDIR(vp->vn_mode )? pmp->pm_dirmask : pmp->pm_mask);

    /*
     * Disallow writing to directories and regular files if the
     * filesystem is read-only.
     */
    if (accmode & VWRITE) {
        switch (vp->vn_mode & S_IFMT) {
        case VREG:
        case VDIR:
            if (vp->v_mount->mode_flags & MNT_RDONLY)
                return -EROFS;
            break;
        default:
            break;
        }
    }

    return vaccess(vp->vn_mode, file_mode, pmp->pm_uid, pmp->pm_gid,
        ap->a_accmode, proc, NULL);
}
#endif

static int
msdosfs_getattr(struct vnode * vp, struct stat * vap, struct proc_info * proc)
{
    struct denode *dep = VTODE(vp);
    struct msdosfsmount *pmp = dep->de_pmp;
    mode_t mode;
    struct timespec ts;
    unsigned long dirsperblk = pmp->pm_BytesPerSec / sizeof(struct direntry);
    uint64_t fileid;

    getnanotime(&ts);
    DETIMES(dep, &ts, &ts, &ts);
    /*
     * The following computation of the fileid must be the same as that
     * used in msdosfs_readdir() to compute d_fileno. If not, pwd
     * doesn't work.
     */
    if (dep->de_Attributes & ATTR_DIRECTORY) {
        fileid = (uint64_t)cntobn(pmp, dep->de_StartCluster) *
            dirsperblk;
        if (dep->de_StartCluster == MSDOSFSROOT)
            fileid = 1;
    } else {
        fileid = (uint64_t)cntobn(pmp, dep->de_dirclust) *
            dirsperblk;
        if (dep->de_dirclust == MSDOSFSROOT)
            fileid = (uint64_t)roottobn(pmp, 0) * dirsperblk;
        fileid += (uoff_t)dep->de_diroffset / sizeof(struct direntry);
    }

    /* TODO */
#if 0
    if (pmp->pm_flags & MSDOSFS_LARGEFS)
        vap->va_fileid = msdosfs_fileno_map(pmp->pm_mountp, fileid);
    else
        vap->va_fileid = (long)fileid;
#endif

    mode = S_IRWXU|S_IRWXG|S_IRWXO;
    vap->st_mode = mode &
        (S_ISDIR(vp->vn_mode) ? pmp->pm_dirmask : pmp->pm_mask);
    vap->st_uid = pmp->pm_uid;
    vap->st_gid = pmp->pm_gid;
    vap->st_nlink = 1;
    vap->st_rdev = 0;
    vap->st_size = dep->de_FileSize;
    fattime2timespec(dep->de_MDate, dep->de_MTime, 0, 0, &vap->st_mtime);
    vap->st_ctime = vap->st_mtime;
    if (pmp->pm_flags & MSDOSFSMNT_LONGNAME) {
        fattime2timespec(dep->de_ADate, 0, 0, 0, &vap->st_atime);
        fattime2timespec(dep->de_CDate, dep->de_CTime, dep->de_CHun,
            0, &vap->st_birthtime);
    } else {
        vap->st_atime = vap->st_mtime;
        vap->st_birthtime.tv_sec = -1;
        vap->st_birthtime.tv_nsec = 0;
    }
    vap->st_flags = 0;
    if (dep->de_Attributes & ATTR_ARCHIVE)
        vap->st_flags |= UF_ARCHIVE;
    if (dep->de_Attributes & ATTR_HIDDEN)
        vap->st_flags |= UF_HIDDEN;
    if (dep->de_Attributes & ATTR_READONLY)
        vap->st_flags |= UF_READONLY;
    if (dep->de_Attributes & ATTR_SYSTEM)
        vap->st_flags |= UF_SYSTEM;
    vap->st_blksize = pmp->pm_bpcluster;
    /* TODO No field for "bytes of disk space held by file" */
#if 0
    vap->va_bytes =
        (dep->de_FileSize + pmp->pm_crbomask) & ~pmp->pm_crbomask;
#endif
    vap->st_mode &= ~S_IFMT;
    vap->st_mode |= vp->vn_mode & S_IFMT;
#if 0
    vap->va_filerev = dep->de_modrev;
#endif

    return 0;
}

static int
msdosfs_setattr(struct vnode * vp, struct stat * vap, proc_info_t * credproc)
{
    struct denode *dep = VTODE(vp);
    struct msdosfsmount *pmp = dep->de_pmp;
    int error = 0;
#ifdef configMSDOSFS_DEBUG
    char msgbuf[80];

    ksprintf(msgbuf, sizeof(msgbuf), "msdosfs_setattr(): vp %p, vap %p\n",
             vp, vap);
    KERROR(KERROR_DEBUG, msgbuf);
#endif

    /*
     * Check for unsettable attributes.
     */
    if (!(vap->st_mode & S_IFMT) || (vap->st_nlink != VNOVAL) ||
        (vap->st_blksize != VNOVAL) || (vap->st_rdev != VNOVAL)/* ||
        (vap->st_bytes != VNOVAL)*/) { /* TODO */
#ifdef configMSDOSFS_DEBUG
        ksprintf(msgbuf, sizeof(msgbuf),
                 "msdosfs_setattr(): returning EINVAL\n");
        KERROR(KERROR_DEBUG, msgbuf);

        ksprintf(msgbuf, sizeof(msgbuf),
                 "    st_mode %d, st_nlink %u, st_dev %u\n",
                 vap->st_mode, vap->st_nlink, vap->st_dev);
        KERROR(KERROR_DEBUG, msgbuf);

        ksprintf(msgbuf, sizeof(msgbuf),
                 "    va_blocksize %u, st_rdev %u\n",
                 vap->st_blksize, vap->st_rdev);
        KERROR(KERROR_DEBUG, msgbuf);

        ksprintf(msgbuf, sizeof(msgbuf),
                 "    va_uid %u, st_gid %u\n",
                 vap->st_uid, vap->st_gid);
        KERROR(KERROR_DEBUG, msgbuf);
#endif
        return -EINVAL;
    }

    /*
     * We don't allow setting attributes on the root directory.
     * The special case for the root directory is because before
     * FAT32, the root directory didn't have an entry for itself
     * (and was otherwise special).  With FAT32, the root
     * directory is not so special, but still doesn't have an
     * entry for itself.
     */
    if (VN_IS_FSROOT(vp))
        return -EINVAL;

    if (vap->st_flags != VNOVAL) {
        if (vp->sb->mode_flags & MNT_RDONLY)
            return -EROFS;
        if (credproc->euid != pmp->pm_uid) {
            error = priv_check_cred(credproc, PRIV_VFS_ADMIN, 0);
            if (error)
                return error;
        }
        /*
         * We are very inconsistent about handling unsupported
         * attributes.  We ignored the access time and the
         * read and execute bits.  We were strict for the other
         * attributes.
         */
        if (vap->st_flags & ~(UF_ARCHIVE | UF_HIDDEN | UF_READONLY |
            UF_SYSTEM))
            return EOPNOTSUPP;
        if (vap->st_flags & UF_ARCHIVE)
            dep->de_Attributes |= ATTR_ARCHIVE;
        else
            dep->de_Attributes &= ~ATTR_ARCHIVE;
        if (vap->st_flags & UF_HIDDEN)
            dep->de_Attributes |= ATTR_HIDDEN;
        else
            dep->de_Attributes &= ~ATTR_HIDDEN;
        /* We don't allow changing the readonly bit on directories. */
        if (!S_ISDIR(vp->vn_mode)) {
            if (vap->st_flags & UF_READONLY)
                dep->de_Attributes |= ATTR_READONLY;
            else
                dep->de_Attributes &= ~ATTR_READONLY;
        }
        if (vap->st_flags & UF_SYSTEM)
            dep->de_Attributes |= ATTR_SYSTEM;
        else
            dep->de_Attributes &= ~ATTR_SYSTEM;
        dep->de_flag |= DE_MODIFIED;
    }

    if (vap->st_uid != (uid_t)VNOVAL || vap->st_gid != (gid_t)VNOVAL) {
        uid_t uid;
        gid_t gid;

        if (vp->sb->mode_flags & MNT_RDONLY)
            return -EROFS;
        uid = vap->st_uid;
        if (uid == (uid_t)VNOVAL)
            uid = pmp->pm_uid;
        gid = vap->st_gid;
        if (gid == (gid_t)VNOVAL)
            gid = pmp->pm_gid;
        if (credproc->euid != pmp->pm_uid || uid != pmp->pm_uid ||
            (gid != pmp->pm_gid && !groupmember(gid, credproc))) {
            error = priv_check_cred(credproc, PRIV_VFS_CHOWN, 0);
            if (error)
                return error;
        }
        if (uid != pmp->pm_uid || gid != pmp->pm_gid)
            return -EINVAL;
    }

    if (vap->st_size != VNOVAL) {
        if (S_ISDIR(vp->vn_mode)) {
            return -EISDIR;
        } else if (S_ISREG(vp->vn_mode)) {
            /*
             * Truncation is only supported for regular files,
             * Disallow it if the filesystem is read-only.
             */
            if (vp->sb->mode_flags & MNT_RDONLY)
                return -EROFS;
        } else {
            /*
             * According to POSIX, the result is unspecified
             * for file types other than regular files,
             * directories and shared memory objects.  We
             * don't support any file types except regular
             * files and directories in this file system, so
             * this (default) case is unreachable and can do
             * anything.  Keep falling through to detrunc()
             * for now.
             */
        }
        error = detrunc(dep, vap->st_size, 0);
        if (error)
            return error;
    }
    if (vap->st_atime.tv_sec != VNOVAL || vap->st_mtime.tv_sec != VNOVAL) {
        if (vp->sb->mode_flags & MNT_RDONLY)
            return -EROFS;
        error = vn_utimes_perm(vp, vap, credproc);
        if (error != 0)
            return error;
        if ((pmp->pm_flags & MSDOSFSMNT_NOWIN95) == 0 &&
            vap->st_atime.tv_sec != VNOVAL) {
            dep->de_flag &= ~DE_ACCESS;
            timespec2fattime(&vap->st_atime, 0,
                &dep->de_ADate, NULL, NULL);
        }
        if (vap->st_mtime.tv_sec != VNOVAL) {
            dep->de_flag &= ~DE_UPDATE;
            timespec2fattime(&vap->st_mtime, 0,
                &dep->de_MDate, &dep->de_MTime, NULL);
        }
        /*
         * We don't set the archive bit when modifying the time of
         * a directory to emulate the Windows/DOS behavior.
         */
        if (!S_ISDIR(vp->vn_mode))
            dep->de_Attributes |= ATTR_ARCHIVE;
        dep->de_flag |= DE_MODIFIED;
    }
    /*
     * DOS files only have the ability to have their writability
     * attribute set, so we use the owner write bit to set the readonly
     * attribute.
     */
    if (vap->st_mode != (mode_t)VNOVAL) {
        if (vp->sb->mode_flags & MNT_RDONLY)
            return -EROFS;
        if (credproc->euid != pmp->pm_uid) {
            error = priv_check_cred(credproc, PRIV_VFS_ADMIN, 0);
            if (error)
                return error;
        }
        if (!S_ISDIR(vp->vn_mode)) {
            /* We ignore the read and execute bits. */
            if (vap->st_mode & (S_IWUSR | S_IWGRP | S_IWOTH))
                dep->de_Attributes &= ~ATTR_READONLY;
            else
                dep->de_Attributes |= ATTR_READONLY;
            dep->de_Attributes |= ATTR_ARCHIVE;
            dep->de_flag |= DE_MODIFIED;
        }
    }
    return deupdat(dep, 0);
}

static ssize_t
msdosfs_read(file_t * file, void * buf, size_t count)
{
    int isadir;
    ssize_t orig_resid;
    unsigned n;
    struct denode * dep = VTODE(file->vnode);
    struct msdosfsmount * pmp = dep->de_pmp;
    int error = 0;

    /*
     * If they didn't ask for any data, then we are done.
     */
    orig_resid = count;
    if (orig_resid == 0)
        return 0;

    isadir = dep->de_Attributes & ATTR_DIRECTORY;
    do {
        int blsize;
        unsigned long on;
        unsigned long diff;
        off_t rablock, lbn;
        struct buf * bp;

        if (file->seek_pos >= dep->de_FileSize)
            break;
        lbn = de_cluster(pmp, file->seek_pos);
        rablock = lbn + 1;
        blsize = pmp->pm_bpcluster;
        on = file->seek_pos & pmp->pm_crbomask;
        /*
         * If we are operating on a directory file then be sure to
         * do i/o with the vnode for the filesystem instead of the
         * vnode for the directory.
         */
        if (isadir) {
            /* convert cluster # to block # */
            error = pcbmap(dep, lbn, &lbn, 0, &blsize);
            if (error == -E2BIG) {
                error = -EINVAL;
                break;
            } else if (error)
                break;
            error = bread(pmp->pm_devvp, lbn, blsize, &bp);
        } else if (de_cn2off(pmp, rablock) >= dep->de_FileSize) {
            error = bread(file->vnode, lbn, blsize, &bp);
        } else {
            error = bread(file->vnode, lbn, blsize, &bp);
        }
        if (error) {
            brelse(bp);
            break;
        }
        diff = pmp->pm_bpcluster - on;
        n = diff > count ? count : diff;
        diff = dep->de_FileSize - file->seek_pos;
        if (diff < n)
            n = diff;
        diff = blsize - count;
        if (diff < n)
            n = diff;
        memmove(buf, (void *)(bp->b_data + on), n);
        brelse(bp);
        count -= n;
        file->seek_pos += n;
    } while (error == 0 && count > 0 && n != 0);
    if (!isadir && (error == 0 || count != orig_resid) &&
        (file->vnode->sb->mode_flags & MNT_NOATIME) == 0)
        dep->de_flag |= DE_ACCESS;

    if (error)
        return error;
    return orig_resid - count;
}

/*
 * Write data to a file or directory.
 */
static int
msdosfs_write(file_t * file, const void * buf, size_t count)
{
    ssize_t resid;
    unsigned long osize;
    off_t lastcn;
    struct vnode * thisvp;
    struct vnode * vp = file->vnode;
    struct denode * dep = VTODE(vp);
    struct msdosfsmount * pmp = dep->de_pmp;
    int error = 0;
#ifdef configMSDOSFS_DEBUG
    char msgbuf[80];

    ksprintf(msgbuf, sizeof(msgbuf),
             "msdosfs_write(file %p, buf %p, count %u)\n",
             file, buf, count);
    KERROR(KERROR_DEBUG, msgbuf);

    ksprintf(msgbuf, sizeof(msgbuf),
             "msdosfs_write(): diroff %lu, dirclust %lu, startcluster %lu\n",
             dep->de_diroffset, dep->de_dirclust, dep->de_StartCluster);
    KERROR(KERROR_DEBUG, msgbuf);
#endif

    if (S_ISREG(vp->vn_mode)) {
        if (file->oflags & O_APPEND)
            file->seek_pos = dep->de_FileSize;
        thisvp = vp;
    } else if (S_ISDIR(vp->vn_mode)) {
        return -EISDIR;
    } else {
        KERROR(KERROR_ERR, "msdosfs_write(): bad file type");

        return -EIO;
    }

    /*
     * This is needed (unlike in ffs_write()) because we extend the
     * file outside of the loop but we don't want to extend the file
     * for writes of 0 bytes.
     */
    if (count == 0)
        return 0;

    if ((uoff_t)file->seek_pos + count > DOS_FILESIZE_MAX)
        return -EFBIG;

    /*
     * If they've exceeded their filesize limit, tell them about it.
     */
    if (vn_rlimit_fsize(file))
        return -EFBIG;

    /*
     * If the offset we are starting the write at is beyond the end of
     * the file, then they've done a seek.  Unix filesystems allow
     * files with holes in them, DOS doesn't so we must fill the hole
     * with zeroed blocks.
     */
    if (file->seek_pos > dep->de_FileSize) {
        error = deextend(dep, file->seek_pos);
        if (error)
            return error;
    }

    /*
     * Remember some values in case the write fails.
     */
    resid = count;
    osize = dep->de_FileSize;

    /*
     * If we write beyond the end of the file, extend it to its ultimate
     * size ahead of the time to hopefully get a contiguous area.
     */
    if (file->seek_pos + resid > osize) {
        size_t ecount;

        ecount = de_clcount(pmp, file->seek_pos + resid) -
            de_clcount(pmp, osize);
        error = extendfile(dep, ecount, NULL, NULL, 0);
        if (error && (error != -ENOSPC))
            goto errexit;
        lastcn = dep->de_fc[FC_LASTFC].fc_frcn;
    } else
        lastcn = de_clcount(pmp, osize) - 1;

    do {
        int n;
        int croffset;
        off_t bn;
        struct buf * bp;

        if (de_cluster(pmp, file->seek_pos) > lastcn) {
            error = -ENOSPC;
            break;
        }

        croffset = file->seek_pos & pmp->pm_crbomask;
        n = min(count, pmp->pm_bpcluster - croffset);
        if (file->seek_pos + n > dep->de_FileSize) {
            dep->de_FileSize = file->seek_pos + n;
            /* The object size needs to be set before buffer is allocated */
            vnode_pager_setsize(vp, dep->de_FileSize);
        }

        bn = de_cluster(pmp, file->seek_pos);
        if ((file->seek_pos & pmp->pm_crbomask) == 0
            && (de_cluster(pmp, file->seek_pos + count)
            > de_cluster(pmp, file->seek_pos)
            || file->seek_pos + count >= dep->de_FileSize)) {
            /*
             * If either the whole cluster gets written,
             * or we write the cluster from its start beyond EOF,
             * then no need to read data from disk.
             */
            bp = getblk(thisvp, bn, pmp->pm_bpcluster, 0);
            vfs_bio_clrbuf(bp);
            /*
             * Do the bmap now, since pcbmap needs buffers
             * for the fat table. (see msdosfs_strategy)
             */
            if (bp->b_blkno == bp->b_lblkno) {
                error = pcbmap(dep, bp->b_lblkno, &bn, 0, 0);
                if (error)
                    bp->b_blkno = -1;
                else
                    bp->b_blkno = bn;
            }
            if (bp->b_blkno == -1) {
                brelse(bp);
                if (!error)
                    error = -EIO;        /* XXX */
                break;
            }
        } else {
            /*
             * The block we need to write into exists, so read it in.
             */
            error = bread(thisvp, bn, pmp->pm_bpcluster, &bp);
            if (error) {
                brelse(bp);
                break;
            }
        }

        /*
         * Copy the data from buffer into the buf header.
         */
        memmove(bp->b_data + croffset, buf, n);
        count -= n;
        file->seek_pos += n;
#if 0 /* Would be used if error can happen on copy */
        if (error) {
            brelse(bp);
            break;
        }
#endif

        /*
         * If O_SYNC, then each buffer is written synchronously.
         * Otherwise, if we have a severe page deficiency then
         * write the buffer asynchronously.  Otherwise, if on a
         * cluster boundary then write the buffer asynchronously,
         * combining it with contiguous clusters if permitted and
         * possible, since we don't expect more writes into this
         * buffer soon.  Otherwise, do a delayed write because we
         * expect more writes into this buffer soon.
         */
        if (file->oflags & O_SYNC)
            (void)bwrite(bp);
#if 0
        else if (vm_page_count_severe() || buf_dirty_count_severe())
            bawrite(bp);
#endif
        else if (n + croffset == pmp->pm_bpcluster)
            bawrite(bp);
        else
            bdwrite(bp);
        dep->de_flag |= DE_UPDATE;
    } while (error == 0 && count > 0);

    /*
     * If the write failed and they want us to, truncate the file back
     * to the size it was before the write was attempted.
     */
errexit:
    if (error) {
        /* TODO Not sure what to do here */
#if 0
        if (ioflag & IO_UNIT) {
#endif
            detrunc(dep, osize, file->oflags & O_SYNC);
            file->seek_pos -= resid - count;
#if 0
        } else {
            detrunc(dep, dep->de_FileSize, file->oflags & O_SYNC);
            if (count != resid)
                error = 0;
        }
#endif
    } else if (file->oflags & O_SYNC)
        error = deupdat(dep, 1);
    return error;
}

#if 0
/*
 * Flush the blocks of a file to disk.
 */
static int
msdosfs_fsync(struct vnode * vp, int waitfor, struct proc_info * proc)
{
    struct vnode * devvp;
    int allerror, error;

    /*
    * If the syncing request comes from fsync(2), sync the entire
    * FAT and any other metadata that happens to be on devvp.  We
    * need this mainly for the FAT.  We write the FAT sloppily, and
    * syncing it all now is the best we can easily do to get all
    * directory entries associated with the file (not just the file)
    * fully synced.  The other metadata includes critical metadata
    * for all directory entries, but only in the MNT_ASYNC case.  We
    * will soon sync all metadata in the file's directory entry.
    * Non-critical metadata for associated directory entries only
    * gets synced accidentally, as in most file systems.
    */
    if (waitfor == MNT_WAIT) {
        devvp = VTODE(vp)->de_pmp->pm_devvp;
        VN_LOCK(devvp);
        allerror = VOP_FSYNC(devvp, MNT_WAIT, proc);
        VN_UNLOCK(devvp, 0);
    } else
        allerror = 0;

    error = deupdat(VTODE(vp), waitfor == MNT_WAIT);
    if (allerror == 0)
        allerror = error;
    return allerror;
}
#endif

static int
msdosfs_remove(struct vnode * dvp, struct vnode * vp,
               const char * name, size_t name_len)
{
    struct denode * dep = VTODE(vp);
    struct denode * ddep = VTODE(dvp);
#ifdef configMSDOSFS_DEBUG
    char msgbuf[80];
#endif
    int error;

    if (S_ISDIR(vp->vn_mode))
        error = -EPERM;
    else
        error = removede(ddep, dep);

#ifdef configMSDOSFS_DEBUG
    ksprintf(msgbuf, sizeof(msgbuf),
           "msdosfs_remove(), dep %p, vn_refcount %d\n",
           dep, vp->vn_refcount);
    KERROR(KERROR_DEBUG, msgbuf);
#endif
    return error;
}

/*
 * DOS filesystems don't know what links are.
 */
static int msdosfs_link(struct vnode * tdvp, struct vnode * vp,
                        const char * name, size_t name_len)
{
    return -EOPNOTSUPP;
}

#if 0
/*
 * Renames on files require moving the denode to a new hash queue since the
 * denode's location is used to compute which hash queue to put the file
 * in. Unless it is a rename in place.  For example "mv a b".
 *
 * What follows is the basic algorithm:
 *
 * if (file move) {
 *  if (dest file exists) {
 *      remove dest file
 *  }
 *  if (dest and src in same directory) {
 *      rewrite name in existing directory slot
 *  } else {
 *      write new entry in dest directory
 *      update offset and dirclust in denode
 *      move denode to new hash chain
 *      clear old directory entry
 *  }
 * } else {
 *  directory move
 *  if (dest directory exists) {
 *      if (dest is not empty) {
 *          return ENOTEMPTY
 *      }
 *      remove dest directory
 *  }
 *  if (dest and src in same directory) {
 *      rewrite name in existing entry
 *  } else {
 *      be sure dest is not a child of src directory
 *      write entry in dest directory
 *      update "." and ".." in moved directory
 *      clear old directory entry for moved directory
 *  }
 * }
 *
 * On entry:
 *  source's parent directory is unlocked
 *  source file or directory is unlocked
 *  destination's parent directory is locked
 *  destination file or directory is locked if it exists
 *
 * On exit:
 *  all denodes should be released
 */
static int
msdosfs_rename(struct vnode * fdvp, struct vnode * fvp,
               const char * name, size_t name_len,
               struct vnode * tdvp, struct vnode * tvp,
               const char * newname, size_t newname_len)
{
    struct denode *ip, *xp, *dp, *zp;
    unsigned char oldname[11];
    unsigned long from_diroffset, to_diroffset;
    unsigned char to_count;
    int doingdirectory = 0, newparent = 0;
    int error;
    unsigned long cn, pcl;
    off_t bn;
    struct denode * fddep;   /* from file's parent directory  */
    struct msdosfsmount * pmp;
    struct direntry * dotdotp;
    struct buf *bp;

    fddep = VTODE(fdvp);
    pmp = fddep->de_pmp;
    /* TODO not sure if it should be the root or omething else */
    pmp = VTODE(fdvp->sb->root)->de_pmp;

#ifdef configMSDOSFS_DEBUG
    if (!name || !newname)
        panic("msdosfs_rename(): no name");
#endif
    /*
     * Check for cross-device rename.
     */
    if (fvp->sb != tdvp->sb ||
        (tvp && fvp->sb != tvp->sb)) {
        error = -EXDEV;
abortit:
        if (tdvp == tvp)
            vrele(tdvp);
        else
            vput(tdvp);
        if (tvp)
            vput(tvp);
        vrele(fdvp);
        vrele(fvp);
        return error;
    }

    /*
     * If source and dest are the same, do nothing.
     */
    if (tvp == fvp) {
        error = 0;
        goto abortit;
    }

    VN_LOCK(fvp);
#if 0
    if (error)
        goto abortit;
#endif
    dp = VTODE(fdvp);
    ip = VTODE(fvp);

    /*
     * Be sure we are not renaming ".", "..", or an alias of ".". This
     * leads to a crippled directory tree.  It's pretty tough to do a
     * "ls" or "pwd" with the "." directory entry missing, and "cd .."
     * doesn't work if the ".." entry is missing.
     */
    if (ip->de_Attributes & ATTR_DIRECTORY) {
        /*
         * Avoid ".", "..", and aliases of "." for obvious reasons.
         */
        if ((name_len == 1 && name[0] == '.') ||
            dp == ip ||
            (fcnp->cn_flags & ISDOTDOT) ||
            (tcnp->cn_flags & ISDOTDOT) ||
            (ip->de_flag & DE_RENAME)) {
            VN_UNLOCK(fvp);
            error = -EINVAL;
            goto abortit;
        }
        ip->de_flag |= DE_RENAME;
        doingdirectory++;
    }

    /*
     * When the target exists, both the directory
     * and target vnodes are returned locked.
     */
    dp = VTODE(tdvp);
    xp = tvp ? VTODE(tvp) : NULL;
    /*
     * Remember direntry place to use for destination
     */
    to_diroffset = dp->de_fndoffset;
    to_count = dp->de_fndcnt;

    /*
     * If ".." must be changed (ie the directory gets a new
     * parent) then the source directory must not be in the
     * directory hierarchy above the target, as this would
     * orphan everything below the source directory. Also
     * the user must have write permission in the source so
     * as to be able to change "..". We must repeat the call
     * to namei, as the parent directory is unlocked by the
     * call to doscheckpath().
     */
    error = VOP_ACCESS(fvp, VWRITE, tcnp->cn_cred, tcnp->cn_thread);
    VN_UNLOCK(fvp);
    if (VTODE(fdvp)->de_StartCluster != VTODE(tdvp)->de_StartCluster)
        newparent = 1;
    if (doingdirectory && newparent) {
        if (error)  /* write access check above */
            goto bad;
        if (xp != NULL)
            vput(tvp);
        /*
         * doscheckpath() vput()'s dp,
         * so we have to do a relookup afterwards
         */
        error = doscheckpath(ip, dp);
        if (error)
            goto out;
        if ((tcnp->cn_flags & SAVESTART) == 0)
            panic("msdosfs_rename: lost to startdir");
        error = relookup(tdvp, &tvp, tcnp);
        if (error)
            goto out;
        dp = VTODE(tdvp);
        xp = tvp ? VTODE(tvp) : NULL;
    }

    if (xp != NULL) {
        /*
         * Target must be empty if a directory and have no links
         * to it. Also, ensure source and target are compatible
         * (both directories, or both not directories).
         */
        if (xp->de_Attributes & ATTR_DIRECTORY) {
            if (!dosdirempty(xp)) {
                error = -ENOTEMPTY;
                goto bad;
            }
            if (!doingdirectory) {
                error = -ENOTDIR;
                goto bad;
            }
            cache_purge(tdvp);
        } else if (doingdirectory) {
            error = -EISDIR;
            goto bad;
        }
        error = removede(dp, xp);
        if (error)
            goto bad;
        vput(tvp);
        xp = NULL;
    }

    /*
     * Convert the filename in tcnp into a dos filename. We copy this
     * into the denode and directory entry for the destination
     * file/directory.
     */
    error = uniqdosname(VTODE(tdvp), newname, newname_len);
    if (error)
        goto abortit;

    /*
     * Since from wasn't locked at various places above,
     * have to do a relookup here.
     */
    fcnp->cn_flags &= ~MODMASK;
    fcnp->cn_flags |= LOCKPARENT | LOCKLEAF;
    if ((fcnp->cn_flags & SAVESTART) == 0)
        panic("msdosfs_rename: lost from startdir");
    if (!newparent)
        VN_UNLOCK(tdvp);
    if (relookup(fdvp, &fvp, fcnp) == 0)
        vrele(fdvp);
    if (fvp == NULL) {
        /*
         * From name has disappeared.
         */
        if (doingdirectory)
            panic("rename: lost dir entry");
        if (newparent)
            VN_UNLOCK(tdvp);
        vrele(tdvp);
        vrele(fvp);
        return 0;
    }
    xp = VTODE(fvp);
    zp = VTODE(fdvp);
    from_diroffset = zp->de_fndoffset;

    /*
     * Ensure that the directory entry still exists and has not
     * changed till now. If the source is a file the entry may
     * have been unlinked or renamed. In either case there is
     * no further work to be done. If the source is a directory
     * then it cannot have been rmdir'ed or renamed; this is
     * prohibited by the DE_RENAME flag.
     */
    if (xp != ip) {
        if (doingdirectory)
            panic("rename: lost dir entry");
        VN_UNLOCK(fvp);
        if (newparent)
            VN_UNLOCK(fdvp);
        vrele(fvp);
        xp = NULL;
    } else {
        vrele(fvp);
        xp = NULL;

        /*
         * First write a new entry in the destination
         * directory and mark the entry in the source directory
         * as deleted.  Then move the denode to the correct hash
         * chain for its new location in the filesystem.  And, if
         * we moved a directory, then update its .. entry to point
         * to the new parent directory.
         */
        memcpy(oldname, ip->de_Name, 11);
        memcpy(ip->de_Name, newname, 11); /* update denode */
        dp->de_fndoffset = to_diroffset;
        dp->de_fndcnt = to_count;
        error = createde(ip, dp, NULL, tcnp);
        if (error) {
            memcpy(ip->de_Name, oldname, 11);
            if (newparent)
                VN_UNLOCK(fdvp);
            VN_UNLOCK(fvp);
            goto bad;
        }
        /*
         * If ip is for a directory, then its name should always
         * be "." since it is for the directory entry in the
         * directory itself (msdosfs_lookup() always translates
         * to the "." entry so as to get a unique denode, except
         * for the root directory there are different
         * complications).  However, we just corrupted its name
         * to pass the correct name to createde().  Undo this.
         */
        if ((ip->de_Attributes & ATTR_DIRECTORY) != 0)
            memmove(ip->de_Name, oldname, 11);
        ip->de_refcnt++;
        zp->de_fndoffset = from_diroffset;
        error = removede(zp, ip);
        if (error) {
            /* XXX should downgrade to ro here, fs is corrupt */
            if (newparent)
                VN_UNLOCK(fdvp);
            VN_UNLOCK(fvp);
            goto bad;
        }
        if (!doingdirectory) {
            error = pcbmap(dp, de_cluster(pmp, to_diroffset), 0,
                       &ip->de_dirclust, 0);
            if (error) {
                /* XXX should downgrade to ro here, fs is corrupt */
                if (newparent)
                    VN_UNLOCK(fdvp);
                VN_UNLOCK(fvp);
                goto bad;
            }
            if (ip->de_dirclust == MSDOSFSROOT)
                ip->de_diroffset = to_diroffset;
            else
                ip->de_diroffset = to_diroffset & pmp->pm_crbomask;
        }
        reinsert(ip);
        if (newparent)
            VN_UNLOCK(fdvp);
    }

    /*
     * If we moved a directory to a new parent directory, then we must
     * fixup the ".." entry in the moved directory.
     */
    if (doingdirectory && newparent) {
        cn = ip->de_StartCluster;
        if (cn == MSDOSFSROOT) {
            /* this should never happen */
            panic("msdosfs_rename(): updating .. in root directory?");
        } else
            bn = cntobn(pmp, cn);
        error = bread(pmp->pm_devvp, bn, pmp->pm_bpcluster, &bp);
        if (error) {
            /* XXX should downgrade to ro here, fs is corrupt */
            brelse(bp);
            VN_UNLOCK(fvp);
            goto bad;
        }
        dotdotp = (struct direntry *)bp->b_data + 1;
        pcl = dp->de_StartCluster;
        if (FAT32(pmp) && pcl == pmp->pm_rootdirblk)
            pcl = MSDOSFSROOT;
        putushort(dotdotp->deStartCluster, pcl);
        if (FAT32(pmp))
            putushort(dotdotp->deHighClust, pcl >> 16);
        if (DOINGASYNC(fvp))
            bdwrite(bp);
        else if ((error = bwrite(bp)) != 0) {
            /* XXX should downgrade to ro here, fs is corrupt */
            VN_UNLOCK(fvp);
            goto bad;
        }
    }

    /*
     * The msdosfs lookup is case insensitive. Several aliases may
     * be inserted for a single directory entry. As a consequnce,
     * name cache purge done by lookup for fvp when DELETE op for
     * namei is specified, might be not enough to expunge all
     * namecache entries that were installed for this direntry.
     */
    cache_purge(fvp);
    VN_UNLOCK(fvp);
bad:
    if (xp)
        vput(tvp);
    vput(tdvp);
out:
    ip->de_flag &= ~DE_RENAME;
    vrele(fdvp);
    vrele(fvp);
    return error;

}
#endif

static struct {
    struct direntry dot;
    struct direntry dotdot;
} dosdirtemplate = {
    {   ".          ",              /* the . entry */
        ATTR_DIRECTORY,             /* file attribute */
        0,                          /* reserved */
        0, { 0, 0 }, { 0, 0 },      /* create time & date */
        { 0, 0 },                   /* access date */
        { 0, 0 },                   /* high bits of start cluster */
        { 210, 4 }, { 210, 4 },     /* modify time & date */
        { 0, 0 },                   /* startcluster */
        { 0, 0, 0, 0 }              /* filesize */
    },
    {   "..         ",              /* the .. entry */
        ATTR_DIRECTORY,             /* file attribute */
        0,                          /* reserved */
        0, { 0, 0 }, { 0, 0 },      /* create time & date */
        { 0, 0 },                   /* access date */
        { 0, 0 },                   /* high bits of start cluster */
        { 210, 4 }, { 210, 4 },     /* modify time & date */
        { 0, 0 },                   /* startcluster */
        { 0, 0, 0, 0 }              /* filesize */
    }
};

static int
msdosfs_mkdir(struct vnode * dvp, struct vnode ** vpp,
              const char * name, size_t name_len, struct stat * vap)
{
    struct denode * dep;
    struct denode * pdep = VTODE(dvp);
    struct direntry * denp;
    struct msdosfsmount * pmp = pdep->de_pmp;
    struct buf * bp;
    unsigned long newcluster, pcl;
    int bn;
    int error;
    struct denode ndirent;
    struct timespec ts;

    /*
     * If this is the root directory and there is no space left we
     * can't do anything.  This is because the root directory can not
     * change size.
     */
    if (pdep->de_StartCluster == MSDOSFSROOT
        && pdep->de_fndoffset >= pdep->de_FileSize) {
        error = -ENOSPC;
        goto bad2;
    }

    /*
     * Allocate a cluster to hold the about to be created directory.
     */
    error = clusteralloc(pmp, 0, 1, CLUST_EOFE, &newcluster, NULL);
    if (error)
        goto bad2;

    memset(&ndirent, '\0', sizeof(ndirent));
    ndirent.de_pmp = pmp;
    ndirent.de_flag = DE_ACCESS | DE_CREATE | DE_UPDATE;
    getnanotime(&ts);
    DETIMES(&ndirent, &ts, &ts, &ts);

    /*
     * Now fill the cluster with the "." and ".." entries. And write
     * the cluster to disk.  This way it is there for the parent
     * directory to be pointing at if there were a crash.
     */
    bn = cntobn(pmp, newcluster);
    /* always succeeds */
    bp = getblk(pmp->pm_devvp, bn, pmp->pm_bpcluster, 0);
    memset((void *)(bp->b_data), '\0', pmp->pm_bpcluster);
    memmove((void *)bp->b_data, &dosdirtemplate, sizeof(dosdirtemplate));
    denp = (struct direntry *)bp->b_data;
    putushort(denp[0].deStartCluster, newcluster);
    putushort(denp[0].deCDate, ndirent.de_CDate);
    putushort(denp[0].deCTime, ndirent.de_CTime);
    denp[0].deCHundredth = ndirent.de_CHun;
    putushort(denp[0].deADate, ndirent.de_ADate);
    putushort(denp[0].deMDate, ndirent.de_MDate);
    putushort(denp[0].deMTime, ndirent.de_MTime);
    pcl = pdep->de_StartCluster;
    /*
     * Although the root directory has a non-magic starting cluster
     * number for FAT32, chkdsk and fsck_msdosfs still require
     * references to it in dotdot entries to be magic.
     */
    if (FAT32(pmp) && pcl == pmp->pm_rootdirblk)
        pcl = MSDOSFSROOT;
    putushort(denp[1].deStartCluster, pcl);
    putushort(denp[1].deCDate, ndirent.de_CDate);
    putushort(denp[1].deCTime, ndirent.de_CTime);
    denp[1].deCHundredth = ndirent.de_CHun;
    putushort(denp[1].deADate, ndirent.de_ADate);
    putushort(denp[1].deMDate, ndirent.de_MDate);
    putushort(denp[1].deMTime, ndirent.de_MTime);
    if (FAT32(pmp)) {
        putushort(denp[0].deHighClust, newcluster >> 16);
        putushort(denp[1].deHighClust, pcl >> 16);
    }

    if (DOINGASYNC(dvp))
        bdwrite(bp);
    else if ((error = bwrite(bp)) != 0)
        goto bad;

    /*
     * Now build up a directory entry pointing to the newly allocated
     * cluster.  This will be written to an empty slot in the parent
     * directory.
     */
#ifdef configMSDOSFS_DEBUG
    if (!name)
        panic("msdosfs_mkdir: no name");
#endif
    error = uniqdosname(pdep, name, name_len, ndirent.de_Name);
    if (error)
        goto bad;

    ndirent.de_Attributes = ATTR_DIRECTORY;
    ndirent.de_LowerCase = 0;
    ndirent.de_StartCluster = newcluster;
    ndirent.de_FileSize = 0;
    error = createde(&ndirent, pdep, &dep, name, name_len);
    if (error)
        goto bad;
    *vpp = DETOV(dep);
    return 0;

bad:
    clusterfree(pmp, newcluster, NULL);
bad2:
    return error;
}

static int
msdosfs_rmdir(struct vnode * dvp, struct vnode * vp,
              const char * name, size_t name_len)
{
    struct denode * ip;
    struct denode * dp;
    int error;

    ip = VTODE(vp);
    dp = VTODE(dvp);

    /*
     * Verify the directory is empty (and valid).
     * (Rmdir ".." won't be valid since
     *  ".." will contain a reference to
     *  the current directory and thus be
     *  non-empty.)
     */
    error = 0;
    if (!dosdirempty(ip) || ip->de_flag & DE_RENAME) {
        error = -ENOTEMPTY;
        goto out;
    }
    /*
     * Delete the entry from the directory.  For dos filesystems this
     * gets rid of the directory entry on disk, the in memory copy
     * still exists but the de_refcnt is <= 0.  This prevents it from
     * being found by deget().  When the vput() on dep is done we give
     * up access and eventually msdosfs_reclaim() will be called which
     * will remove it from the denode cache.
     */
    error = removede(dp, ip);
    if (error)
        goto out;
    /*
     * This is where we decrement the link count in the parent
     * directory.  Since dos filesystems don't do this we just purge
     * the name cache.
     */
    cache_purge(dvp);
    /*
     * Truncate the directory that is being deleted.
     */
    error = detrunc(ip, (unsigned long)0, O_SYNC);
    cache_purge(vp);

out:
    return error;
}

/*
 * DOS filesystems don't know what symlinks are.
 */
static int
msdosfs_symlink(struct vnode * dvp, struct vnode ** vpp,
                const char * name, size_t name_len, struct stat * vap,
                char * target)
{
    return -EOPNOTSUPP;
}

static int
msdosfs_readdir(vnode_t * vp, struct dirent * d, off_t * doff)
{
    struct mbnambuf nb;
    int error = 0;
    int diff;
    long n;
    int blsize;
    long on;
    unsigned long cn;
    uint64_t fileno;
    unsigned long dirsperblk;
    long bias = 0;
    off_t bn, lbn;
    struct buf * bp;
    struct denode * dep = VTODE(vp);
    struct msdosfsmount * pmp = dep->de_pmp;
    struct direntry * dentp;
    struct dirent dirbuf;
    off_t offset, off;
    int chksum = -1;
#ifdef configMSDOSFS_DEBUG
    char msgbuf[80];

    ksprintf(msgbuf, sizeof(msgbuf), "msdosfs_readdir(): vp %p\n", vp);
    KERROR(KERROR_DEBUG, msgbuf);
#endif

    /*
     * msdosfs_readdir() won't operate properly on regular files since
     * it does i/o only with the filesystem vnode, and hence can
     * retrieve the wrong block from the buffer cache for a plain file.
     * So, fail attempts to readdir() on a plain file.
     */
    if ((dep->de_Attributes & ATTR_DIRECTORY) == 0)
        return -ENOTDIR;

    /*
     * To be safe, initialize dirbuf
     */
    memset(dirbuf.d_name, '\0', sizeof(dirbuf.d_name));

    /* TODO Get rid of this! */
    if (*doff == 0x00000000FFFFFFFF)
        *doff = 0;
    off = offset = *doff;

    dirsperblk = pmp->pm_BytesPerSec / sizeof(struct direntry);

    /*
     * If they are reading from the root directory then, we simulate
     * the . and .. entries since these don't exist in the root
     * directory.  We also set the offset bias to make up for having to
     * simulate these entries. By this I mean that at file offset 64 we
     * read the first entry in the root directory that lives on disk.
     */
    if (dep->de_StartCluster == MSDOSFSROOT
        || (FAT32(pmp) && dep->de_StartCluster == pmp->pm_rootdirblk)) {
        bias = 2 * sizeof(struct direntry);
        if (offset < bias) {
            for (n = (int)offset / sizeof(struct direntry);
                 n < 2; n++) {
                if (FAT32(pmp)) {
                    fileno = (uint64_t)
                             cntobn(pmp, pmp->pm_rootdirblk) * dirsperblk;
                } else {
                    fileno = 1;
                }
                if (pmp->pm_flags & MSDOSFS_LARGEFS) {
                    dirbuf.d_ino = msdosfs_fileno_map(pmp->pm_mountp, fileno);
                } else {

                    dirbuf.d_ino = (uint32_t)fileno;
                }
                dirbuf.d_type = DT_DIR;
                switch (n) {
                case 0:
                    //dirbuf.d_namlen = 1;
                    strcpy(dirbuf.d_name, ".");
                    break;
                case 1:
                    //dirbuf.d_namlen = 2;
                    strcpy(dirbuf.d_name, "..");
                    break;
                }
                //dirbuf.d_reclen = GENERIC_DIRSIZ(&dirbuf);
                offset += sizeof(struct direntry);
                off = offset;

                *d = dirbuf; /* Copy */
                goto out;
            }
        }
    }

    mbnambuf_init(&nb);
    off = offset;

    lbn = de_cluster(pmp, offset - bias);
    on = (offset - bias) & pmp->pm_crbomask;
    n = min(pmp->pm_bpcluster - on, sizeof(struct direntry));
    diff = dep->de_FileSize - (offset - bias);
    if (diff <= 0)
        goto out;
    n = min(n, diff);
    error = pcbmap(dep, lbn, &bn, &cn, &blsize);
    if (error)
        goto out;
    error = bread(pmp->pm_devvp, bn, blsize, &bp);
    if (error) {
        brelse(bp);
        return error;
    }
    n = min(n, blsize - bp->b_resid);
    if (n == 0) {
        brelse(bp);
        return -EIO;
    }

    /*
     * Convert from dos directory entries to fs-independent
     * directory entries.
     */
    for (dentp = (struct direntry *)(bp->b_data + on);
         (char *)dentp < bp->b_data + on + n;
         dentp++, offset += sizeof(struct direntry)) {
#if 0
        ksprintf(msgbuf, sizeof(msgbuf),
                 "rd: dentp %08x prev %08x crnt %08x deName %02x attr %02x\n",
                 dentp, prev, crnt, dentp->deName[0], dentp->deAttributes);
        KERROR(KERROR_DEBUG, msgbuf);
#endif
        /*
         * If this is an unused entry, we can stop.
         */
        if (dentp->deName[0] == SLOT_EMPTY) {
            brelse(bp);
            goto out;
        }
        /*
         * Skip deleted entries.
         */
        if (dentp->deName[0] == SLOT_DELETED) {
            chksum = -1;
            mbnambuf_init(&nb);
            continue;
        }

        /*
         * Handle Win95 long directory entries
         */
        if (dentp->deAttributes == ATTR_WIN95) {
            if (pmp->pm_flags & MSDOSFSMNT_SHORTNAME)
                continue;
            chksum = win2unixfn(&nb,
                (struct winentry *)dentp, chksum, pmp);
            continue;
        }

        /*
         * Skip volume labels
         */
        if (dentp->deAttributes & ATTR_VOLUME) {
            chksum = -1;
            mbnambuf_init(&nb);
            continue;
        }
        /*
         * This computation of d_fileno must match
         * the computation of va_fileid in
         * msdosfs_getattr.
         */
        if (dentp->deAttributes & ATTR_DIRECTORY) {
            fileno = getushort(dentp->deStartCluster);
            if (FAT32(pmp))
                fileno |= getushort(dentp->deHighClust) << 16;
            /* if this is the root directory */
            if (fileno == MSDOSFSROOT)
                if (FAT32(pmp))
                    fileno = (uint64_t)cntobn(pmp,
                            pmp->pm_rootdirblk)
                         * dirsperblk;
                else
                    fileno = 1;
            else
                fileno = (uint64_t)cntobn(pmp, fileno) *
                    dirsperblk;
            dirbuf.d_type = DT_DIR;
        } else {
            fileno = (uoff_t)offset /
                sizeof(struct direntry);
            dirbuf.d_type = DT_REG;
        }
        if (pmp->pm_flags & MSDOSFS_LARGEFS) {
            dirbuf.d_ino =
                msdosfs_fileno_map(pmp->pm_mountp, fileno);
        } else
            dirbuf.d_ino = (uint32_t)fileno;

        if (chksum != winChksum(dentp->deName)) {
#if 0
            dirbuf.d_namlen = dos2unixfn(dentp->deName,
                (unsigned char *)dirbuf.d_name,
                dentp->deLowerCase |
                ((pmp->pm_flags & MSDOSFSMNT_SHORTNAME) ?
                (LCASE_BASE | LCASE_EXT) : 0),
                pmp);
#endif
            mbnambuf_init(&nb);
        } else
            mbnambuf_flush(&nb, &dirbuf);
        chksum = -1;

        *d = dirbuf; /* copy */
        off = offset + sizeof(struct direntry);
    }
    brelse(bp);

out:
    *doff = off;

    return error;
}

/*-
 * a_vp   - pointer to the file's vnode
 * a_bn   - logical block number within the file (cluster number for us)
 * a_bnp  - where to return the "physical" block number corresponding to a_bn
 *          (relative to the special file; units are blocks of size DEV_BSIZE)
 * a_runp - where to return the "run past" a_bn.  This is the count of logical
 *          blocks whose physical blocks (together with a_bn's physical block)
 *          are contiguous.
 * a_runb - where to return the "run before" a_bn.
 */
static int
msdosfs_bmap(struct vnode * vp, off_t  bn, off_t * bnp, int * runp, int * runb)
{
    struct denode * dep = VTODE(vp);
    struct fs_superblock * mp;
    struct msdosfsmount * pmp = dep->de_pmp;
    off_t runbn;
    unsigned long cn;
    int bnpercn, error, maxio, maxrun, run;

    if (bnp == NULL)
        return 0;
    if (runp != NULL)
        *runp = 0;
    if (runb != NULL)
        *runb = 0;
    cn = bn;
    if (cn != bn)
        return -EFBIG;
    error = pcbmap(dep, cn, bnp, NULL, NULL);
    if (error != 0 || (runp == NULL && runb == NULL))
        return error;

    mp = vp->sb;
    //TODO maxio = mp->mnt_iosize_max / mp->mnt_stat.f_iosize;
    maxio = 1;
    bnpercn = de_cn2bn(pmp, 1);
    if (runp != NULL) {
        maxrun = ulmin(maxio - 1, pmp->pm_maxcluster - cn);
        for (run = 1; run <= maxrun; run++) {
            if (pcbmap(dep, cn + run, &runbn, NULL, NULL) != 0 ||
                runbn != *bnp + run * bnpercn)
                break;
        }
        *runp = run - 1;
    }
    if (runb != NULL) {
        maxrun = ulmin(maxio - 1, cn);
        for (run = 1; run < maxrun; run++) {
            if (pcbmap(dep, cn - run, &runbn, NULL, NULL) != 0 ||
                runbn != *bnp - run * bnpercn)
                break;
        }
        *runb = run - 1;
    }

    return 0;
}

/* TODO Not needed for zeke? */
#if 0
static int
msdosfs_strategy(struct vnode * vp, struct buf * bp)
{
    struct denode * dep = VTODE(vp);
    int error = 0;
    off_t blkno;

    /*
     * If we don't already know the filesystem relative block number
     * then get it using pcbmap().  If pcbmap() returns the block
     * number as -1 then we've got a hole in the file.  DOS filesystems
     * don't allow files with holes, so we shouldn't ever see this.
     */
    if (bp->b_blkno == bp->b_lblkno) {
        error = pcbmap(dep, bp->b_lblkno, &blkno, 0, 0);
        bp->b_blkno = blkno;
        if (error) {
            bp->b_error = error;
            bp->b_flags |= B_IOERROR;
            bufdone(bp);

            return 0;
        }
        if ((long)bp->b_blkno == -1)
            vfs_bio_clrbuf(bp);
    }
    if (bp->b_blkno == -1) {
        bufdone(bp);

        return 0;
    }
    /*
     * Read/write the block from/to the disk that contains the desired
     * file block.
     */
    //bp->b_iooffset = dbtob(bp->b_blkno); TODO Do we need this?
    //bo = dep->de_pmp->pm_bo;
    //BO_STRATEGY(bo, bp);
    // TODO call strategy()?
    return 0;
}
#endif

static int
msdosfs_print(struct vnode * vp)
{
    struct denode * dep = VTODE(vp);
    char * devname = devtoname(dep->de_pmp->pm_devvp);
    char msgbuf[120];

    ksprintf(msgbuf, sizeof(msgbuf),
             "\tstartcluster %lu, dircluster %lu, diroffset %lu, on dev %s\n",
             dep->de_StartCluster, dep->de_dirclust, dep->de_diroffset,
             (devname) ? devname : "NOT A DEVICE");
    KERROR(KERROR_INFO, msgbuf);

    return 0;
}

/* TODO Not yet implemented */
#if 0
static int
msdosfs_pathconf(struct vnode * vp, int name, int * retval)
{
    struct msdosfsmount * pmp = VTODE(vp)->de_pmp;

    switch (name) {
    case _PC_LINK_MAX:
        *retval = 1;
        return 0;
    case _PC_NAME_MAX:
        *retval = pmp->pm_flags & MSDOSFSMNT_LONGNAME ? WIN_MAXLEN : 12;
        return 0;
    case _PC_PATH_MAX:
        *retval = PATH_MAX;
        return 0;
    case _PC_CHOWN_RESTRICTED:
        *retval = 1;
        return 0;
    case _PC_NO_TRUNC:
        *retval = 0;
        return 0;
    default:
        return -EINVAL;
    }
    /* NOTREACHED */
}
#endif

static int
msdosfs_vptofh(struct vnode * vp, struct fid * fhp)
{
    struct denode * dep = VTODE(vp);
    struct defid *defhp;

    defhp = (struct defid *)fhp;
    defhp->defid_len = sizeof(struct defid);
    defhp->defid_dirclust = dep->de_dirclust;
    defhp->defid_dirofs = dep->de_diroffset;
    /* defhp->defid_gen = dep->de_gen; */

    return 0;
}

/* Global vfs data structures for msdosfs */
struct vnode_ops msdosfs_vnode_ops = {
    .write =        msdosfs_write,
    .read =         msdosfs_read,
    .create =       msdosfs_create,
    .mknod =        msdosfs_mknod,
    .lookup =       msdosfs_lookup,
    .link =         msdosfs_link,
    //.unlink =       msdosfs_unlink,
    .mkdir =        msdosfs_mkdir,
    .rmdir =        msdosfs_rmdir,
    .readdir =      msdosfs_readdir,
    .stat =         msdosfs_getattr,
    //.chmod =        msdosfs_chmod,
    //.chown =        msdosfs_chown
#if 0 /* BSD */
    .vop_default =      &default_vnodeops,

    .vop_access =       msdosfs_access,
    .vop_bmap =         msdosfs_bmap,
    .vop_cachedlookup = msdosfs_lookup,
    .vop_open =         msdosfs_open,
    .vop_close =        msdosfs_close,
    .vop_create =       msdosfs_create,
    .vop_fsync =        msdosfs_fsync,
    .vop_getattr =      msdosfs_getattr,
    .vop_inactive =     msdosfs_inactive,
    .vop_link =         msdosfs_link,
    .vop_lookup =       vfs_cache_lookup,
    .vop_mkdir =        msdosfs_mkdir,
    .vop_mknod =        msdosfs_mknod,
    .vop_pathconf =     msdosfs_pathconf,
    .vop_print =        msdosfs_print,
    .vop_read =     msdosfs_read,
    .vop_readdir =      msdosfs_readdir,
    .vop_reclaim =      msdosfs_reclaim,
    .vop_remove =       msdosfs_remove,
    .vop_rename =       msdosfs_rename,
    .vop_rmdir =        msdosfs_rmdir,
    .vop_setattr =      msdosfs_setattr,
    .vop_strategy =     msdosfs_strategy,
    .vop_symlink =      msdosfs_symlink,
    .vop_write =        msdosfs_write,
    .vop_vptofh =       msdosfs_vptofh,
#endif
};
