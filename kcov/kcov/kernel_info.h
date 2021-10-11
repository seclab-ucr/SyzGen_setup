//
//  kernel_info.h
//  kcov
//
//  Created by Weiteng Chen on 12/23/20.
//  Copyright © 2020 wchen130. All rights reserved.
//

#ifndef kernel_info_h
#define kernel_info_h

#include <mach/mach_types.h>

struct kernel_info {
    mach_vm_address_t kaslr_slide;
    // Below is for testing only
    mach_vm_address_t idt_addr;
};
extern struct kernel_info g_kernel_info;

kern_return_t init_kernel_info(struct kernel_info *kinfo);

mach_vm_address_t get_kaslr_slide(void);

#endif /* kernel_info_h */
