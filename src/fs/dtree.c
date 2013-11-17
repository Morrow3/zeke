/**
 *******************************************************************************
 * @file    dtree.h
 * @author  Olli Vanhoja
 * @brief   dtree - directory tree headers.
 *          dtree is used for directory structure lookup caching.
 * @section LICENSE
 * Copyright (c) 2013 Olli Vanhoja <olli.vanhoja@cs.helsinki.fi>
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

/** @addtogroup fs
  * @{
  */

#ifndef PU_TEST_BUILD
#include <kmalloc.h>
#else
#include <stdlib.h>
#define kmalloc malloc
#define kfree free
#endif
#include <kstring.h>
#include "dtree.h"

#ifndef PU_TEST_BUILD
#define DESTROY_PREFIX static void
#else
#define DESTROY_PREFIX void
#endif
DESTROY_PREFIX dtree_destroy_node(dtree_node_t * node);
static size_t hash_fname(char * fname, size_t len);
static void cond_truncate(void);

#ifndef PU_TEST_BUILD
#define DT_SIZE_MAX configFS_CACHE_MAX
#else
#define DT_SIZE_MAX 200
#endif
static int dt_size = 0; /*!< Size of dtree ignoring fnames. */

dtree_node_t dtree_root = {
    .fname = "/", /* Special case, any other fname should not contain '/'. */
    .parent = &dtree_root, /* In POSIX "/" is parent of itself. */
    .pchild[0] = &dtree_root,
    .persist = 1
};

/**
 * Create a new dtree node.
 * @param parent is the parent node of the new node.
 * @param fname is the name of the new node. (will be copied)
 * @param persist != 0 to make this node persistent.
 * @return Returns a pointer to the new node; 0 if failed.
 */
dtree_node_t * dtree_create_node(dtree_node_t * parent, char * fname, int persist)
{
    dtree_node_t * nnode = 0;
    char * nname;
    int nlen;
    size_t i;

    if (parent == 0) {
        goto out;
    }
    if (parent->fname == 0) {
        goto out;
    }

    nnode = kmalloc(sizeof(dtree_node_t));
    if (nnode == 0)
        goto out;

    nlen = strlenn(fname, 255);
    nname = kmalloc(nlen);
    if (nname == 0)
        goto free_nnode;

    cond_truncate();

    /* Initialize the new node */
    memcpy(nname, fname, nlen);
    nnode->fname = nname;
    nnode->parent = parent;
    memset(nnode->pchild, 0, DTREE_HTABLE_SIZE);
    memset(nnode->child, 0, DTREE_HTABLE_SIZE);

    /* Add as a child of parent */
    if (persist) {
        for (i = 0; i < DTREE_HTABLE_SIZE; i++) {
            if (parent->pchild[i] == 0) {
                parent->pchild[i] = nnode;
                break;
            }
        }
        parent->persist++;
    } else {
        size_t hash = hash_fname(fname, nlen);
        if (parent->child[hash] != 0) {
            dtree_remove_node(parent->child[hash], 1);
        }
        parent->child[hash] = nnode;
    }

    goto out; /* Ready */

free_nnode:
    kfree(nnode);
    nnode = 0;
out:
    return nnode;
}

/**
 * Remove a dtree node and its children.
 * @param node is the node to be removed.
 * @param dpers if != 0 removes also persisted nodes.
 * @return 0 if succeed; Value other than 0 if failed.
 */
int dtree_remove_node(dtree_node_t * node, int dpers)
{
    size_t i;
    dtree_node_t * parent;
    int retval = 0;

    if (node == 0) {
        goto out;
    }

    for (i = 0; i < DTREE_HTABLE_SIZE; i++) {
        if (dpers) dtree_remove_node(node->child[i], 1);
        retval = dtree_remove_node(node->child[i], dpers);
    }

    if (node->persist > 0 || retval != 0) {
        retval = 2;
        goto out;
    }

    parent = node->parent;
    for (i = 0; i < DTREE_HTABLE_SIZE; i++) {
        if (parent->pchild[i] == node) {
            if (dpers) {
                retval = 0;
                parent->pchild[i] = 0;
            } else retval = 1;
        }
        if (parent->child[i] == node) {
            parent->child[i] = 0;
        }
    }

    if (retval == 0)
        dtree_destroy_node(node);

out:
    return retval;
}

/**
 * Destroy dtree node.
 * @note Removes also persisted nodes.
 */
DESTROY_PREFIX dtree_destroy_node(dtree_node_t * node)
{
    if (node == 0)
        return;

    if (node->fname != 0)
        kfree(node->fname);
    kfree(node);

    dt_size -= sizeof(dtree_node_t);
}

size_t path_compare(char * fname, char * path, size_t offset)
{
    size_t i = 0;

    while (path[offset] != '/' && path[offset] != '\0' && fname[i] != '\0'
            && (path[offset] == fname[i])) {
        offset++;
        i++;
    }
    if ((path[offset] == '/' || path[offset] == '\0') && fname[i] == '\0')
        return offset;
    return 0;
}

dtree_node_t * dtree_lookup(char * path)
{
    size_t i, k, prev_k;
    size_t hash;
    dtree_node_t * retval = 0;

    if (path[0] != '/')
        goto out;

    retval = &dtree_root;
    k = 0;
    while (path[++k] != '\0') {
        prev_k = k;

        /* First look from child htable */
        i = k;
        while (path[i] != '\0' && path[i] != '/') { i++; }
        hash = hash_fname(&(path[k]), i - k);
        if (retval->child[hash] != 0) {
            size_t j;
            j = path_compare(retval->child[hash]->fname, path, k);
            if (j != 0) {
                retval = retval->child[hash];
                k = j;
                continue;
            }
        }

        /* if no hit, then from pchild array */
        for (i = 0; i < DTREE_HTABLE_SIZE; i++) {
            if (retval->pchild[i] != 0) {
                k = path_compare(retval->pchild[i]->fname, path, k);
                if (k != 0) {
                    retval = retval->pchild[i];
                    break;
                }
            }
        }
        if (k == 0 || k == prev_k) {
            break;
        }
    }

out:
    return retval;
}

static size_t hash_fname(char * fname, size_t len)
{
    /* TODO larger hash space if DTREE_HTABLE_SIZE > sizeof char */
    size_t hash = (fname[0] ^ fname[len - 1]) & (DTREE_HTABLE_SIZE - 1);

    return hash;
}

static void cond_truncate(void)
{
    dt_size += sizeof(dtree_node_t);
    if (dt_size > DT_SIZE_MAX) {
        dtree_remove_node(&dtree_root, 0);
    }
}

/**
  * @}
  */