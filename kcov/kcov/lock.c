//
//  lock.c
//  kcov
//
//  Created by 陈伟腾 on 12/26/20.
//  Copyright © 2020 wchen130. All rights reserved.
//

#include <kern/locks.h>
#include <i386/proc_reg.h>

#include "lock.h"
#include "common.h"

//
// CR0 and mutex lock
//
unsigned long cr0;
lck_mtx_t *cr0_lock;
lck_grp_t *glock_group;

//
// Disable the write protection bit in CR0 register
//
void
disable_write_protection() {
    lck_mtx_lock(cr0_lock);
    unsigned long tmp_cr0 = cr0 = get_cr0();
    tmp_cr0 &= ~CR0_WP;
    set_cr0(tmp_cr0);
}

//
// Enable the write protection bit in CR0 register
//
void
enable_write_protection(
    )
{
    unsigned long tmp_cr0 = cr0;
    set_cr0(tmp_cr0);
    cr0 = 0;
    lck_mtx_unlock(cr0_lock);
}

void
disable_write_protection_without_lock(
    )
{
    unsigned long tmp_cr0 = cr0 = get_cr0();
    tmp_cr0 &= ~CR0_WP;
    set_cr0(tmp_cr0);
}

void
enable_write_protection_without_lock(
    )
{
    unsigned long tmp_cr0 = cr0;
    set_cr0(tmp_cr0);
    cr0 = 0;
}

kern_return_t
init_mutex() {
    glock_group = lck_grp_alloc_init(DRIVER_CTL_NAME, LCK_GRP_ATTR_NULL);
    if (!glock_group)
        return KERN_NO_SPACE;
    
    cr0_lock = lck_mtx_alloc_init(glock_group, LCK_ATTR_NULL);
    if (!cr0_lock)
        return KERN_NO_SPACE;
    
    return KERN_SUCCESS;
}

void
free_mutex() {
    if (cr0_lock && glock_group) {
        lck_mtx_free(cr0_lock, glock_group);
        cr0_lock = NULL;
    }
    
    if (glock_group) {
        lck_grp_free(glock_group);
        glock_group = NULL;
    }
}
