//
//  file.c
//  kcov
//
//  Created by Weiteng Chen on 12/29/20.
//  Copyright © 2020 wchen130. All rights reserved.
//

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/malloc.h>
#include <sys/uio.h>
#include <libkern/libkern.h>
#include <sys/vnode.h>

#include "file.h"

static
size_t
getFileSize(
    vnode_t vnode,
    vfs_context_t ctx
    )
{
    struct vnode_attr va;
    VATTR_INIT(&va);
    VATTR_WANTED(&va, va_data_size);
    return vnode_getattr(vnode, &va, ctx) ? 0 : va.va_data_size;
}

static
int
performFileIO(
    void *buf,
    off_t off,
    size_t size,
    vnode_t vnode,
    vfs_context_t ctx,
    bool write
    )
{
    uio_t uio = uio_create(1, off, UIO_SYSSPACE, write ? UIO_WRITE : UIO_READ);
    if (!uio) {
        printf("uio_create return null!\n");
        return EINVAL;
    }
    
    int error = uio_addiov(uio, CAST_USER_ADDR_T(buf), size);
    if (error) {
        printf("uio_addiov returned error %d!", error);
        return error;
    }
    
    if (write)
        error = VNOP_WRITE(vnode, uio, 0, ctx);
    else
        error = VNOP_READ(vnode, uio, 0, ctx);
    if (error) {
        printf("%s failed %d!", write ? "VNOP_WRITE" : "VNOP_READ", error);
        return error;
    }

    if (uio_resid(uio)) {
        printf("uio_resid returned non-null!");
        return EINVAL;
    }

    return 0;
}

static
int
readFileData(
    void *buf,
    off_t off,
    size_t size,
    vnode_t vnode,
    vfs_context_t ctx
    )
{
    return performFileIO(buf, off, size, vnode, ctx, false);
}

uint8_t*
readFile(
    const char *path,
    size_t *size
    )
{
    uint8_t *buf = NULL;
    vnode_t vnode = NULLVP;
    vfs_context_t vfs = NULL;
    if ((vfs = vfs_context_create(NULL)) == NULL) {
        return NULL;
    }
    if (vnode_lookup(path, 0, &vnode, vfs)) {
        printf("failed to find %s\n", path);
        goto release;
    }
    size_t count = getFileSize(vnode, vfs);
    *size = count;
    if (count > 0) {
        buf = _MALLOC(count, M_TEMP, M_ZERO);
        if (buf) {
            if (readFileData(buf, 0, count, vnode, vfs)) {
                _FREE(buf, M_TEMP);
                buf = NULL;
            }
        }
    } else {
        printf("failed to get file size\n");
    }
    
    vnode_put(vnode);
release:
    if (vfs) {
        vfs_context_rele(vfs);
    }
    return buf;
}
