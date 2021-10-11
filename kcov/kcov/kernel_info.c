//
//  kernel_info.c
//  kcov
//
//  Created by Weiteng Chen on 12/23/20.
//  Copyright © 2020 wchen130. All rights reserved.
//

#include <kern/debug.h>
#include <sys/vnode.h>

#include "common.h"
#include "kernel_info.h"
#include "gen.h"

struct kernel_info g_kernel_info = { .kaslr_slide = 0 };

mach_vm_address_t get_kaslr_slide() {
    mach_vm_address_t slide = (mach_vm_address_t)panic - PANIC_OFFSET;
    if (slide > 0x100000000 || (slide&0x1000) != 0) {
        // make sure slide is positive and its alignemnt is correct.
        return 0;
    }
    return slide;
}

kern_return_t
init_kernel_info(struct kernel_info *kinfo) {
    kern_return_t error = KERN_SUCCESS;
    
    kinfo->kaslr_slide = get_kaslr_slide();
    if (kinfo->kaslr_slide == 0) {
        return KERN_FAILURE;
    }
    return error;
}

mach_vm_address_t get_addr(void) {
    return (mach_vm_address_t)panic;
}


