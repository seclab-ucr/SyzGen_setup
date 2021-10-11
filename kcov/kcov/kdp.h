//
//  kdp.h
//  kcov
//
//  Created by Weiteng Chen on 12/24/20.
//  Copyright © 2020 wchen130. All rights reserved.
//

#ifndef kdp_h
#define kdp_h

#include <mach/kmod.h>

#define NUM_OF_KCOV 1
typedef struct kcov {
    uint64_t *area;
    bool     enable;
} kcov_t;
extern kcov_t *gKcov[NUM_OF_KCOV];

kern_return_t init_kmod(kmod_info_t *ki);
void uninit_kmod(void);

void
kdp_raise_exception_handler(
    unsigned int exception,
    unsigned int code,
    unsigned int subcode,
    void *saved_state);

kern_return_t load_breakpoints(void);
kern_return_t install_breakpoints(char *name, uint64_t *addrs, unsigned int size);

void test_install_breakpoints(void* data);

void show_breakpoints(void *data, size_t *size);

#endif /* kdp_h */
