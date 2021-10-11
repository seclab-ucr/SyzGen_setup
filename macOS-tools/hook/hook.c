//
//  hook.c
//  hook
//
//  Created by Weiteng Chen on 6/7/20.
//  Copyright © 2020 wchen130. All rights reserved.
//

// sudo chown -R root:wheel hook.kext
// sudo kextload hook.kext
//

#include <sys/systm.h>
#include <mach/mach_types.h>
#include <os/log.h>
#include <sys/fcntl.h>
#include <sys/vnode.h>
#include <sys/kern_control.h>
#include <sys/proc.h>
#include <kern/locks.h>
#include <i386/proc_reg.h>
#include <IOKit/IOLib.h>

#include "gen.h"
#include "include.h"

kern_return_t hook_start(kmod_info_t * ki, void *d);
kern_return_t hook_stop(kmod_info_t *ki, void *d);

static kmod_info_t* tgtKext = NULL;

//
// Disable the write protection bit in CR0 register
//
static void disable_write_protection() {
    lck_mtx_lock(cr0_lock);
    unsigned long tmp_cr0 = cr0 = get_cr0();
    tmp_cr0 &= ~CR0_WP;
    set_cr0(tmp_cr0);
}

//
// Enable the write protection bit in CR0 register
//
static void enable_write_protection() {
    unsigned long tmp_cr0 = cr0;
    set_cr0(tmp_cr0);
    cr0 = 0;
    lck_mtx_unlock(cr0_lock);
}

static kern_return_t init_mutex() {
    glock_group = lck_grp_alloc_init(HOOK_CTL_NAME, LCK_GRP_ATTR_NULL);
    if (!glock_group)
        return KERN_NO_SPACE;
    
    cr0_lock = lck_mtx_alloc_init(glock_group, LCK_ATTR_NULL);
    if (!cr0_lock)
        return KERN_NO_SPACE;
    
    return KERN_SUCCESS;
}

static void free_mutex() {
    if (cr0_lock && glock_group) {
        lck_mtx_free(cr0_lock, glock_group);
        cr0_lock = NULL;
    }
    
    if (glock_group) {
        lck_grp_free(glock_group);
        glock_group = NULL;
    }
}

static errno_t getHookFuncs(void *data, size_t len) {
    if (tgtKext == NULL) {
        return EINVAL;
    }

    // Introduce a bug here, to be removed later.
    vm_address_t routine_ptr = 0;
    *(uint64_t*)routine_ptr = 0;
    return KERN_SUCCESS;
}

static errno_t getHookEntries(void *data, size_t* len) {
    if (gHookMode != HOOK_MODE_NONE) {
        printf("[%s.kext] Please disable hooking before get any info to avoid race\n", DRIVER_NAME);
        return EINVAL;
    }
    
    size_t size = *len;
    size_t max_num = size / sizeof(Entry);
    if (max_num > gEntryIndex) {
        max_num = gEntryIndex;
    }
    memcpy(data, entries, max_num * sizeof(Entry));
    *len = max_num * sizeof(Entry);
    return KERN_SUCCESS;
}

//
// IOMemoryDescriptor *
// IOMemoryDescriptor::withAddressRange(mach_vm_address_t address,
//     mach_vm_size_t length,
//     IOOptionBits   options,
//     task_t         task)
//
static long withAddressRangeStub(volatile long arg0, volatile long arg1, volatile long arg2,
                                 volatile long arg3, volatile long arg4, volatile long arg5,
                                 volatile long arg6, volatile long arg7, volatile long arg8,
                                 volatile long arg9) {
    if (gHookMode == HOOK_MODE_LISTEN) {
#if DO_LOG
        printf("[%s.kext] withAddressRange ptr: 0x%lx, size: %ld, opt: %ld\n", DRIVER_NAME, arg0, arg1, arg2);
#endif
        if (gPid == 0 || gPid == proc_selfpid()) {
            // ensure no data race
            lck_mtx_lock(cr0_lock);
            
            gWithAddressRangeCmd.header.type = HOOK_WITHADDRESSRANGE;
            gWithAddressRangeCmd.header.size = __offsetof(CMD_WITHADDRESSRANGE, data) + arg1 - sizeof(CMD_HEADER);
            gWithAddressRangeCmd.header.pid = proc_selfpid();
            gWithAddressRangeCmd.addr = arg0;
            gWithAddressRangeCmd.size = arg1;
            if (arg1 < 4096 && copyin(arg0, gWithAddressRangeCmd.data, arg1) == 0) {
                ctl_enqueuedata(gKeCtlRef, gkeCtlSacUnit, &gWithAddressRangeCmd,
                                __offsetof(CMD_WITHADDRESSRANGE, data) + arg1, 0);
            }
            
            lck_mtx_unlock(cr0_lock);
        }
    }
    return gWithAddressRange.originFunc(arg0, arg1, arg2, arg3, arg4, arg5, arg6,
                                        arg7, arg8, arg9);
}

//
// virtual IOReturn externalMethod(this, uint32_t selector, IOExternalMethodArguments *arguments,
//   IOExternalMethodDispatch *dispatch, OSObject *target, void *reference);
//
static long externalMethodStub(volatile long arg0, volatile long arg1, volatile long arg2,
                               volatile long arg3, volatile long arg4, volatile long arg5,
                               volatile long arg6, volatile long arg7, volatile long arg8,
                               volatile long arg9) {
#if DO_LOG
    printf("[%s.kext] externalMethod selector: %u\n", DRIVER_NAME, (uint32_t) arg1);
#endif
    bool skip = (gPid != 0 && proc_selfpid() != gPid);
    if (!skip) {
        struct IOExternalMethodArguments *args = (struct IOExternalMethodArguments*) arg2;
        if (gHookMode == HOOK_MODE_LISTEN) {
            // ensure no data race
            lck_mtx_lock(cr0_lock);
            
            gPreExternalMethodCmd.header.type = HOOK_PRE_EXTERNALMETHOD;
            gPreExternalMethodCmd.header.size = __offsetof(CMD_PRE_EXTERNALMETHOD, data) + args->structureInputSize - sizeof(CMD_HEADER);
            gPreExternalMethodCmd.header.pid = proc_selfpid();
            gPreExternalMethodCmd.connection = arg0;
            gPreExternalMethodCmd.selector   = (uint32_t) arg1;
            gPreExternalMethodCmd.outputStructSize = args->structureOutputSize;
            gPreExternalMethodCmd.scalarOutputCount = args->scalarOutputCount;
            
            gPreExternalMethodCmd.scalarInputCount = args->scalarInputCount;
            if (args->scalarInputCount)
                memcpy(gPreExternalMethodCmd.scalarInput, args->scalarInput, args->scalarInputCount*sizeof(uint64_t));
            
            gPreExternalMethodCmd.inputStructSize = args->structureInputSize;
            if (args->structureInputSize) {
                memcpy(gPreExternalMethodCmd.data, args->structureInput, args->structureInputSize);
            }
            ctl_enqueuedata(gKeCtlRef, gkeCtlSacUnit, &gPreExternalMethodCmd,
                            __offsetof(CMD_PRE_EXTERNALMETHOD, data) + args->structureInputSize, 0);
            
            lck_mtx_unlock(cr0_lock);
        }
    }
    
    long ret = gExternalMethod.originFunc(arg0, arg1, arg2, arg3, arg4, arg5, arg6,
                                      arg7, arg8, arg9);
    
    if (!skip && gHookMode == HOOK_MODE_LISTEN) {
        lck_mtx_lock(cr0_lock);
        
        // copy out output
        struct IOExternalMethodArguments *args = (struct IOExternalMethodArguments*) arg2;
        gPostExternalMethodCmd.header.type = HOOK_POST_EXTERNALMETHOD;
        gPostExternalMethodCmd.header.size = __offsetof(CMD_POST_EXTERNALMETHOD, data) + args->structureOutputSize - sizeof(CMD_HEADER);
        gPostExternalMethodCmd.header.pid = proc_selfpid();
        
        gPostExternalMethodCmd.scalarOutputCount = args->scalarOutputCount;
        if (args->scalarOutputCount)
            memcpy(gPostExternalMethodCmd.scalarOutput, args->scalarOutput, args->scalarOutputCount*sizeof(uint64_t));
        
        gPostExternalMethodCmd.outputStructSize = args->structureOutputSize;
        if (args->structureOutputSize)
            memcpy(gPostExternalMethodCmd.data, args->structureOutput, args->structureOutputSize);
        
        if (args->scalarOutputCount || args->structureOutputSize)
            ctl_enqueuedata(gKeCtlRef, gkeCtlSacUnit, &gPostExternalMethodCmd,
                __offsetof(CMD_POST_EXTERNALMETHOD, data) + args->structureOutputSize, 0);
        
        lck_mtx_unlock(cr0_lock);
    }
    
    return ret;
}

static errno_t hook_initialize(vm_address_t base) {
    kern_return_t status = KERN_SUCCESS;
    
    disable_interrupts();
    disable_write_protection();
    
    // Hook vtable
    vm_address_t externalMethod = base + EXTERNALMETHOD_OFFSET;
    gExternalMethod.originFunc = *(syscall_t*)externalMethod;
    gExternalMethod.hookFunc = &externalMethodStub;
    *(syscall_t*)externalMethod = gExternalMethod.hookFunc;
    
    // Hook all library calls to withAddressRange
    vm_address_t org_withAddressRange = 0;
    for (int i = 0; i < sizeof(Offset2WithAddressRange) / sizeof(uint32_t); i++) {
        vm_address_t patch_addr = base + Offset2WithAddressRange[i];
        // FIXME: Here we assume the offset is of 4 bytes
        uint32_t offset = *(uint32_t*)patch_addr;
        vm_address_t withAddressRange = patch_addr + 4 + offset;
        if (org_withAddressRange == 0) {
            org_withAddressRange = withAddressRange;
        } else if (org_withAddressRange != withAddressRange) {
            printf("[%s.kext] Unmatched address for withAddressRange", DRIVER_NAME);
            status = KERN_FAILURE;
            break;
        }
        vm_address_t target = (vm_address_t)&withAddressRangeStub;
        vm_address_t off = target - (patch_addr + 4);
        *(uint32_t*)patch_addr = (uint32_t)off;
#if DO_LOG
//        printf("[%s.kext] WithAddressRange: 0x%lx 0x%lx, off: 0x%x\n", DRIVER_NAME, withAddressRange, target, off);
#endif
    }
    gWithAddressRange.originFunc = (syscall_t)org_withAddressRange;
    gWithAddressRange.hookFunc = &withAddressRangeStub;
    
    enable_write_protection();
    enable_interrupts();
    
    return status;
}

static void hook_recover() {
    if (tgtKext == NULL) return;
    
    disable_interrupts();
    disable_write_protection();
    
    // recover vtable
    if (gExternalMethod.originFunc != 0) {
        vm_address_t externalMethod = tgtKext->address + EXTERNALMETHOD_OFFSET;
        *(syscall_t*)externalMethod = gExternalMethod.originFunc;
    }
    
    // recover withAddressRange
    if (gWithAddressRange.originFunc != 0) {
        for (int i = 0; i < sizeof(Offset2WithAddressRange) / sizeof(uint32_t); i++) {
            vm_address_t patch_addr = tgtKext->address + Offset2WithAddressRange[i];
            // FIXME: Here we assume the offset is of 4 bytes
            vm_address_t off = (vm_address_t)gWithAddressRange.originFunc - (patch_addr + 4);
            *(uint32_t*)patch_addr = (uint32_t)off;
        }
    }
    
    
    enable_write_protection();
    enable_interrupts();
}

static void reset_entry() {
    bzero(entries, sizeof(Entry) * gEntryIndex);
    gEntryIndex = gLastIndex = 0;
}

errno_t HookHandleSetOpt(kern_ctl_ref ctlref, unsigned int unit, void *userdata, int opt, void *data, size_t len) {
#if DO_LOG
    printf("[%s.kext] call setOpt %d...\n", DRIVER_NAME, opt);
#endif
    int error = KERN_INVALID_VALUE;
    switch (opt) {
        case SOCKOPT_SET_ENABLE:
            reset_entry();
            gHookMode = HOOK_MODE_RECORD;
            if (len == 4) {
                gPid = *(int*)data;
                return KERN_SUCCESS;
            }
            break;
        case SOCKOPT_SET_DISABLE:
            gHookMode = HOOK_MODE_NONE;
            gPid = -1;
            return KERN_SUCCESS;
        case SOCKOPT_SET_RESET:
            reset_entry();
            return KERN_SUCCESS;
        case SOCKOPT_SET_LISTEN:
            gHookMode = HOOK_MODE_LISTEN;
            if (len == 4) {
                gPid = *(int*)data;
                return KERN_SUCCESS;
            }
            break;
//        case SOCKOPT_SET_TEST:
//            gHookMode = HOOK_MODE_TEST;
//            if (len == 4) {
//                gPid = *(int*)data;
//                return KERN_SUCCESS;
//            }
//            break;
        default:
            break;
    }
    return error;
}

errno_t HookHandleGetOpt(kern_ctl_ref ctlref, unsigned int unit, void *userdata, int opt, void *data, size_t *len) {
#if DO_LOG
    printf("[%s.kext] call getOpt %d...\n", DRIVER_NAME, opt);
#endif
    int error = EINVAL;
    switch (opt) {
        case SOCKOPT_GET_TEST:
            error = getHookFuncs(data, *len);
            break;
        case SOCKOPT_GET_READ:
            error = getHookEntries(data, len);
            break;
        default:
            break;
    }
    return error;
}

errno_t HookHandleConnect(kern_ctl_ref ctlref, struct sockaddr_ctl *sac, void **unitinfo) {
#if DO_LOG
    printf("[%s.kext] call connect...\n", DRIVER_NAME);
#endif
    gKeCtrlConnected = 1;
    gkeCtlSacUnit = sac->sc_unit;
    return KERN_SUCCESS;
}

errno_t HookhandleDisconnect(kern_ctl_ref ctlref, unsigned int unit, void *unitinfo) {
#if DO_LOG
    printf("[%s.kext] call disconnect...\n", DRIVER_NAME);
#endif
    gHookMode = HOOK_MODE_NONE;
    reset_entry();
    gKeCtrlConnected = 0;
    gkeCtlSacUnit = 0;
    return KERN_SUCCESS;
}

errno_t HookHandleSend(kern_ctl_ref ctlref, unsigned int unit, void *userdata, mbuf_t m, int flags) {
#if DO_LOG
    printf("[%s.kext] call send...\n", DRIVER_NAME);
#endif
    int error = EINVAL;
    return error;
}

void kernelControl_register() {
    errno_t err;
    bzero(&gKeCtlReg, sizeof(struct kern_ctl_reg));
    strncpy(gKeCtlReg.ctl_name, HOOK_CTL_NAME, strlen(HOOK_CTL_NAME));
    gKeCtlReg.ctl_flags      =    CTL_FLAG_REG_SOCK_STREAM;
    gKeCtlReg.ctl_setopt     =    HookHandleSetOpt;
    gKeCtlReg.ctl_getopt     =    HookHandleGetOpt;
    gKeCtlReg.ctl_connect    =    HookHandleConnect;
    gKeCtlReg.ctl_disconnect =    HookhandleDisconnect;
    gKeCtlReg.ctl_send       =    HookHandleSend;
    
    err = ctl_register(&gKeCtlReg, &gKeCtlRef);
    if (err == KERN_SUCCESS) {
        printf("Register KerCtlConnection success: id=%d", gKeCtlReg.ctl_id);
    } else {
        printf("Fail to register: err=%d", err);
    }
}

void kernelControl_deregister() {
    if (gKeCtlRef == NULL) {
        return;
    }
    
    errno_t err = ctl_deregister(gKeCtlRef);
    if (err) {
        printf("Fail to deregister: err=%d",err);
    }
    gKeCtlRef = NULL;
}

kern_return_t hook_start(kmod_info_t * ki, void *d)
{
    kern_return_t status = KERN_SUCCESS;
    printf("[%s.kext] Hook kext has started.\n", DRIVER_NAME);
    kernelControl_register();
    if ((status = init_mutex()) != KERN_SUCCESS) {
        goto fail;
    }
    
    //
    // Dump the kernel module list
    //
    
    char kmod_buffer[0x100];
    unsigned long kmod_length = sizeof(kmod_buffer);
    kmod_info_t *kmod_item = ki;
    int index = 0;

    do {
        memset(kmod_buffer, 0, kmod_length);
#if DO_LOG
        snprintf(kmod_buffer, kmod_length,
                 "[%s.kext] : module name=%s, module version=%s, module base=0x%lx, module size=0x%lx, module start=%p, module stop=%p.\n",
                 DRIVER_NAME, kmod_item->name, kmod_item->version,
                 kmod_item->address, kmod_item->size,
                 kmod_item->start, kmod_item->stop);
        printf("%s\n", kmod_buffer);
        printf("id: %d, kmod_info: %p\n", index, kmod_item);
#endif

        if (!strcmp(TARGET_KEXT, kmod_item->name)) {
            tgtKext = kmod_item;
            status = hook_initialize(kmod_item->address);
            break;
        }
        
        kmod_item = kmod_item->next;
        index++;
    } while (kmod_item);
    
    if (kmod_item == 0) {
        printf("[%s.kext] Failed to find the target!!\n", DRIVER_NAME);
        status = KERN_FAILURE;
    }
    
fail:
    if (status != KERN_SUCCESS) {
        free_mutex();
        hook_stop(ki, d);
    }
    return status;
}

kern_return_t hook_stop(kmod_info_t *ki, void *d)
{
    printf("[%s.kext] Hook kext has stopped.\n", DRIVER_NAME);
    kernelControl_deregister();
    hook_recover();
    return KERN_SUCCESS;
}
