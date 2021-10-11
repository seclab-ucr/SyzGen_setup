//
//  kdp.c
//  kcov
//
//  Created by Weiteng Chen on 12/24/20.
//  Copyright © 2020 wchen130. All rights reserved.
//

#include <stdint.h>
#include <mach/mach_types.h>
#include <string.h>
#include <sys/malloc.h>
#include <libkern/libkern.h>
#include <sys/vnode.h>

#include "kdp.h"
#include "lock.h"
#include "gen.h"
#include "common.h"
#include "kernel_info.h"
#include "file.h"

#include "hashmap/hashmap.h"

kcov_t *gKcov[NUM_OF_KCOV] = {NULL};

// Copy from osfmk/mach/i386/thread_status.h
#pragma pack(4)

/*
 * This is the state pushed onto the 64-bit interrupt stack
 * on any exception/trap/interrupt.
 */
struct x86_64_intr_stack_frame {
    uint16_t        trapno;
    uint16_t        cpu;
    uint32_t        _pad;
    uint64_t        trapfn;
    uint64_t        err;
    uint64_t        rip;
    uint64_t        cs;
    uint64_t        rflags;
    uint64_t        rsp;
    uint64_t        ss;
};
typedef struct x86_64_intr_stack_frame x86_64_intr_stack_frame_t;
_Static_assert((sizeof(x86_64_intr_stack_frame_t) % 16) == 0,
    "interrupt stack frame size must be a multiple of 16 bytes");

/*
 * thread state format for task running in 64bit long mode
 * in long mode, the same hardware frame is always pushed regardless
 * of whether there was a change in privilege level... therefore, there
 * is no need for an x86_saved_state64_from_kernel variant
 */
struct x86_saved_state64 {
    uint64_t        rdi;            /* arg0 for system call */
    uint64_t        rsi;
    uint64_t        rdx;
    uint64_t        r10;            /* R10 := RCX prior to syscall trap */
    uint64_t        r8;
    uint64_t        r9;             /* arg5 for system call */

    uint64_t        cr2;
    uint64_t        r15;
    uint64_t        r14;
    uint64_t        r13;
    uint64_t        r12;
    uint64_t        r11;
    uint64_t        rbp;
    uint64_t        rbx;
    uint64_t        rcx;
    uint64_t        rax;

    uint32_t        gs;
    uint32_t        fs;

    uint32_t        ds;
    uint32_t        es;

    struct  x86_64_intr_stack_frame isf;
};
typedef struct x86_saved_state64 x86_saved_state64_t;

//
// Info for all loaded kexts
//
typedef struct kext_info {
    char                name[KMOD_MAX_NAME];
    vm_address_t        address;            // starting address
    vm_size_t           size;               // total size
} kext_info_t;
static kext_info_t *kext_infos = 0;
static unsigned int num_of_kext = 0;

//
// Config file for breakpoints
//
typedef struct kcov_header_t {
    char     name[KMOD_MAX_NAME];
    uint64_t size;
    uint64_t addrs[1];  // variable length indicated by size
} kcov_header_t;

//
// Hashmap to store breakpoints
//

static struct hashmap *breakpoint_map = NULL;

uint8_t breakinstr[1] = {0xcc};
typedef struct Breakpoint {
    uint64_t address;
    uint64_t originaddr;
    uint8_t oldbytes[sizeof(breakinstr)];
} breakpoint_t;

uint64_t bp_hash(const void *item, uint64_t seed0, uint64_t seed1) {
    const breakpoint_t *bp = item;
    return hashmap_sip(&bp->address, sizeof(uint64_t), seed0, seed1);
}

int bp_compare(const void *a, const void *b, void *udata) {
    const breakpoint_t *bpa = a;
    const breakpoint_t *bpb = b;
    return (int) (bpa->address - bpb->address);
}

/*
 * This function is meant to be invoked by our handler of kdp_raise_exception, in which
 * case disable_preemption has been called to prevent other intervention and thus we do
 * not need to and can not lock in any thread. We, therefore, use disable_write_protection_without_lock and enable_write_protection_without_lock.
 */
static
kern_return_t
uninstall_breakpoint_internal(
    uint64_t addr,
    uint64_t *origin_addr
    )
{
    breakpoint_t key = { .address = addr };
    breakpoint_t *bp = hashmap_get(breakpoint_map, &key);
    if (bp == NULL) {
        return KERN_FAILURE;
    }
    *origin_addr = bp->originaddr;

    disable_interrupts();
    disable_write_protection_without_lock();
    
//    printf("[%s.kext] uninstall 0x%llx with 0x%x\n", DRIVER_NAME, bp->address, bp->oldbytes[0]);
    memcpy((void *)addr, bp->oldbytes, sizeof(breakinstr));
    
    enable_write_protection_without_lock();
    enable_interrupts();
    
    hashmap_delete(breakpoint_map, &key);
    return KERN_SUCCESS;
}

static
bool
bp_iter_uninstall(
    const void *item,
    void *udata
    )
{
    const breakpoint_t *bp = item;
//    printf("[%s.kext] uninstall 0x%llx with 0x%x\n", DRIVER_NAME, bp->address, bp->oldbytes[0]);
    
    disable_interrupts();
    disable_write_protection();
    
    memcpy((void *)bp->address, bp->oldbytes, sizeof(breakinstr));
    
    enable_write_protection();
    enable_interrupts();
    
    return true;
}

static size_t bp_show_total = 0;
static size_t bp_show_index = 0;

static
bool
bp_iter_show(
    const void *item,
    void *udata
    )
{
    if (bp_show_index >= bp_show_total)
        return false;
    
    const breakpoint_t *bp = item;
    memcpy((void *)((breakpoint_t *)udata + bp_show_index), bp, sizeof(breakpoint_t));
    bp_show_index++;
    return true;
}

static
void
uninstall_breakpoints(
    )
{
    printf("uninstall breakpoints\n");
    if (breakpoint_map == NULL) {
        return;
    }

    hashmap_scan(breakpoint_map, bp_iter_uninstall, NULL);
    hashmap_free(breakpoint_map);
    breakpoint_map = NULL;
}

void
show_breakpoints(
    void *data,
    size_t *size
    )
{
    if (breakpoint_map != NULL) {
        size_t count = *size / sizeof(breakpoint_t);
        bp_show_total = count;
        bp_show_index = 0;
        hashmap_scan(breakpoint_map, bp_iter_show, data);
        *size = bp_show_index * sizeof(breakpoint_t);
    }
}

/*
 * Require Write Permission
 */
static
kern_return_t
install_breakpoint_internal(
    uint64_t addr,
    uint64_t origin_addr
    )
{
    breakpoint_t bp = { .address = addr, .originaddr = origin_addr };
    if (hashmap_get(breakpoint_map, &bp)) {
        // Already exists
        return KERN_FAILURE;
    }
    memcpy(bp.oldbytes, (void *)addr, sizeof(breakinstr));
    
    // The interrupt should be enabled while allocating memory, and thus we have to
    // tightly wrap the memcpy to avoid any conflict.
    disable_interrupts();
    disable_write_protection();
    
    memcpy((void *)addr, (void *)breakinstr, sizeof(breakinstr));
    
    enable_write_protection();
    enable_interrupts();
    
    hashmap_set(breakpoint_map, &bp);
    return KERN_SUCCESS;
}

kern_return_t
install_breakpoints(
    char *name,
    uint64_t *addrs,
    unsigned int size)
{
    if (kext_infos == 0)
        return KERN_FAILURE;
    
    if (!strcmp(name, "kernel")) {
        // hook kernel
        for (unsigned i = 0; i < size; i++) {
            uint64_t vm_addr = addrs[i] + g_kernel_info.kaslr_slide;
            install_breakpoint_internal(vm_addr, addrs[i]);
        }
    } else {
        // hook driver
        for (unsigned i = 0; i < num_of_kext; i++) {
            if (!strcmp(name, kext_infos[i].name)) {
                for (unsigned j = 0; j < size; j++) {
                    uint64_t vm_addr = (uint64_t) (addrs[j] + kext_infos[i].address);
                    install_breakpoint_internal(vm_addr, addrs[j]);
                }
                break;
            }
        }
    }
    
    return KERN_SUCCESS;
}

void
kdp_raise_exception_handler(
    unsigned int exception,
    unsigned int code,
    unsigned int subcode,
    void *saved_state) {
    
    x86_saved_state64_t *state = (x86_saved_state64_t*) saved_state;
    uint64_t rip = state->isf.rip - sizeof(breakinstr);
//    printf("[%s.kext] kdp_raise_exception with rip 0x%llx\n", DRIVER_NAME, rip);
    
    // Recover the patched instruction
    uint64_t origin_addr;
    if (uninstall_breakpoint_internal(rip, &origin_addr) == KERN_SUCCESS) {
        // Rewind the pc
        state->isf.rip = rip;
        // TODO: How to get the corresponding kcov. Currently we always choose the first one.
        if (gKcov[0] && gKcov[0]->area) {
            uint64_t *addr = (uint64_t *)gKcov[0]->area;
            uint64_t pos = addr[0] + 1;
            if (pos < COVER_SIZE/sizeof(uint64_t)) {
                // FIXME: we need to know which driver it refers to. Right now we assume we only
                // have one driver of interest.
                addr[pos] = origin_addr;
                addr[0] = pos;
            }
        } else {
            printf("failed to record pc\n");
        }
    }
}

kern_return_t
load_breakpoints(
    )
{
    size_t size;
    uint8_t *buf = readFile(KCOV_FILE, &size);
    if (buf == NULL) {
        return KERN_FAILURE;
    }
    
    // The first 4 byte is the size of drivers
    uint64_t count = *(uint64_t *)buf;
    uint8_t *data = buf + sizeof(uint64_t);
    if (count != 1) {
        // currently we only support one driver
        goto free;
    }
    for (uint64_t i = 0; i < count; i++) {
        kcov_header_t *head = (kcov_header_t *)data;
        printf("[%s.kext] install breakpoints %s %llu\n", DRIVER_NAME, head->name, head->size);
        install_breakpoints(head->name, &(head->addrs[0]), (unsigned)head->size);
//        install_breakpoints(head->name, &(head->addrs[0]), 32);
        data += (__offsetof(kcov_header_t, addrs) + head->size * sizeof(uint64_t));
    }
    
free:
    _FREE(buf, M_TEMP);
    return KERN_SUCCESS;
}

void
test_install_breakpoints(
    void* data
    )
{
    size_t size;
    uint8_t *buf = readFile(KCOV_FILE, &size);
    if (buf == NULL) {
        return;
    }
    memcpy(data, buf, sizeof(uint64_t) + __offsetof(kcov_header_t, addrs) + 32*sizeof(uint64_t));
    _FREE(buf, M_TEMP);
}

kern_return_t
init_kmod(
    kmod_info_t *ki
    )
{
    // convert the list of info into a simple array.
    kmod_info_t *kmod_item = ki;
    int count = 0;
    do {
        kmod_item = kmod_item->next;
        count++;
    } while (kmod_item);
    
    kext_infos = _MALLOC(count*sizeof(kext_info_t), M_TEMP, M_ZERO);
    if (kext_infos == 0) {
        return KERN_NO_SPACE;
    }
    num_of_kext = count;
    
    kmod_item = ki;
    count = 0;
    do {
        kext_infos[count].address = kmod_item->address;
        kext_infos[count].size = kmod_item->size;
        strncpy(kext_infos[count].name, kmod_item->name, KMOD_MAX_NAME);
        count++;
        kmod_item = kmod_item->next;
    } while (kmod_item);
    
    breakpoint_map = hashmap_new(sizeof(breakpoint_t), 0, 0, 0, bp_hash, bp_compare, NULL);
    if (breakpoint_map == NULL) {
        printf("[%s.kext] failed to create hashmap.\n", DRIVER_NAME);
        return KERN_NO_SPACE;
    }
    
    return KERN_SUCCESS;
}

void
uninit_kmod(
    )
{
    uninstall_breakpoints();
    
    if (kext_infos) {
        _FREE(kext_infos, M_TEMP);
        num_of_kext = 0;
    }
}
