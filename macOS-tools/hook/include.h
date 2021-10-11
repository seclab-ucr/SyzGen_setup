
//
//  include.h
//  hook
//
//  Created by Weiteng Chen on 6/7/20.
//  Copyright © 2020 wchen130. All rights reserved.
//

#ifndef include_h
#define include_h

//#include <libkern/libkern.h>

#include "common.h"

#define DRIVER_NAME "Hook"
#define DO_LOG  0


#define ENCODE_PTR(ptr, size, opt) (ptr | (size << 48) | (opt << 60))
#define GET_PTR(ptr) (ptr & 0xffffffffffff)
#define GET_SIZE(ptr) ((ptr >> 48) & 0xfff)
#define GET_OPT(ptr) ((ptr >> 60) & 0xf)

// FIXME: How to deal with multi threads
unsigned int gEntryIndex = 0;
unsigned int gLastIndex = 0;

//
// CR0 and mutex lock
//
unsigned long cr0;
lck_mtx_t *cr0_lock;
lck_grp_t *glock_group;

typedef intptr_t(*syscall_t)(intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t, intptr_t);
typedef struct hooker {
    syscall_t originFunc;
    syscall_t hookFunc;
} Hooker;

// Hook functions
Hooker gExternalMethod = {0};
Hooker gWithAddressRange = {0};
unsigned gHookMode = HOOK_MODE_NONE;

// controller related (only one process)
struct kern_ctl_reg gKeCtlReg = {0};
kern_ctl_ref gKeCtlRef = NULL;
unsigned int gKeCtrlConnected = 0;
unsigned int gkeCtlSacUnit = 0;
int gPid = -1;

#if DO_LOG
bool gDoLog = true;
#else
bool gDoLog = false;
#endif

//
// Enable and disable interrupts
//

#define disable_interrupts() __asm__ volatile ("cli");
#define enable_interrupts() __asm__ volatile ("sti");

// see <IOKit/IOUserClient.h>
struct IOExternalMethodArguments {
    uint32_t            version;

    uint32_t            selector;

    mach_port_t           asyncWakePort;
    void * asyncReference;
    uint32_t              asyncReferenceCount;

    const uint64_t *    scalarInput;
    uint32_t            scalarInputCount;

    void *              structureInput;
    uint32_t            structureInputSize;

    void * structureInputDescriptor;

    uint64_t *          scalarOutput;
    uint32_t            scalarOutputCount;

    void *              structureOutput;
    uint32_t            structureOutputSize;

    void * structureOutputDescriptor;
    uint32_t             structureOutputDescriptorSize;

    uint32_t            __reservedA;

    void **         structureVariableOutputData;

    uint32_t            __reserved[30];
};

#endif /* include_h */
