//
//  hook.c
//  kcov
//
//  Created by Weiteng Chen on 12/24/20.
//  Copyright © 2020 wchen130. All rights reserved.
//

#include <libkern/libkern.h>

#include "distorm/include/distorm.h"
#include "hook.h"
#include "common.h"
#include "gen.h"
#include "kdp.h"
#include "lock.h"

#define MAX_INSTRUCTIONS 15
#define HOOK_KDP_RAISE_EXCEPTION 0

// Trampoline
static uint64_t jmp_to_kdp_raise_exception_handler = 0;
static uint64_t jmp_back_to_kdp_raise_exception = 0;
static unsigned int kdp_raise_exception_patch_size = 0;
static bool enable_kdp_raise_exception = false;
static char kdp_raise_exception_origin_bytes[OFFSET_OF_PLACEHOLDER_IN_TRAMPOLINE] = {0};
Trampoline(kdp_raise_exception, jmp_to_kdp_raise_exception_handler, jmp_back_to_kdp_raise_exception)
Inlined_code(kdp_raise_exception);

/*
* We have two mode of hooking. First one is the traditional one where we save the first few
* instructions from the hooked function to our trampoline and patch the hooked function to
* to jump to our trampoline which will jump back to the original function. In which case, 'origin'
* should be our trampoline plus some offset (OFFSET_OF_PLACEHOLDER_IN_TRAMPOLINE).
* The second one is a completely replacement in which we patch the original function to directly
* jump to our handler and it won't jump back to the original one. In this case, the 'origin'
* should a separate array used to save original instructions.
*/
static
kern_return_t
install_inline_hook(
    void *target,
    unsigned int size,
    void *trampoline,
    char *origin,
    char *inline_code,
    unsigned int inline_code_size
    )
{
    disable_interrupts();
    disable_write_protection();
    
    // Copy first few instructions from the hooked function to our trampoline
    memcpy((void *)origin, target, size);
    // Patch inlined code to make sure hooked function can call our tampoline.
    *(uint64_t *) (inline_code + 2) = (uint64_t) trampoline;
    // Inject the inlined code into the hooked function.
    memcpy(target, inline_code, inline_code_size);
    
    enable_write_protection();
    enable_interrupts();
    return KERN_SUCCESS;
}

static
void
uninstall_inline_hook(
    void *target,
    unsigned int size,
    char *origin
    )
{
    disable_interrupts();
    disable_write_protection();
    
    // Copy back the original instructions from trampoline.
    memcpy(target, (void *)origin, size);
    
    enable_write_protection();
    enable_interrupts();
}

static
unsigned int
calculate_instruction_size(
    void *target
    )
{
    _DecodeResult result;
    _DecodedInst decoded_instructions[MAX_INSTRUCTIONS];
    _DecodeType decode_type = Decode64Bits;
    unsigned char *buffer = (unsigned char*) target;
    // maximum size of instructions we can hold.
    int length = SIZE_OF_PLACEHOLDER_IN_TRAMPOLINE;
    unsigned int total_bytes = 0, decoded_instructions_count = 0;
    
    while (1) {
        result = distorm_decode64((_OffsetType)buffer,
                                  buffer,
                                  length,
                                  decode_type,
                                  decoded_instructions,
                                  MAX_INSTRUCTIONS,
                                  &decoded_instructions_count);
        if (result == DECRES_INPUTERR) {
            printf("[%s.kext] Cound not disassemble code at 0x%llx\n", DRIVER_NAME, (mach_vm_address_t)target);
            return 0;
        }
        
        for (unsigned int index = 0; index < decoded_instructions_count; index++) {
            total_bytes += decoded_instructions[index].size;
            buffer += decoded_instructions[index].size;
            length -= decoded_instructions[index].size;
            if (sizeof(kdp_raise_exception_inline) <= total_bytes) {
                if (total_bytes > SIZE_OF_PLACEHOLDER_IN_TRAMPOLINE) {
                    printf("[%s.kext] placeholder is too small for 0x%llx\n", DRIVER_NAME, (mach_vm_address_t)target);
                    return 0;
                }
                return total_bytes;
            }
        }
        
        // All instructions are decoded or no instruction is decoded.
        if (DECRES_SUCCESS == result || !decoded_instructions_count) {
            break;
        }
    }
    
    return 0;
}

static
void
unhook_kdp_raise_exception(
    struct kernel_info *kinfo
    )
{
    if (enable_kdp_raise_exception) {
        mach_vm_address_t kdp_raise_exception_addr = KDP_RAISE_EXCEPTION + kinfo->kaslr_slide;
#if HOOK_KDP_RAISE_EXCEPTION
        uninstall_inline_hook((void*)kdp_raise_exception_addr,
                              kdp_raise_exception_patch_size,
                              (char*)kdp_raise_exception_trampoline + OFFSET_OF_PLACEHOLDER_IN_TRAMPOLINE);
#else
        uninstall_inline_hook((void *)kdp_raise_exception_addr,
                              kdp_raise_exception_patch_size,
                              kdp_raise_exception_origin_bytes);
#endif
        enable_kdp_raise_exception = false;
    }
}

kern_return_t
hook_start(kmod_info_t *ki, struct kernel_info *kinfo) {
    kern_return_t err = KERN_SUCCESS;
    if ((err = init_mutex()) != KERN_SUCCESS) {
        printf("[%s.kext] failed to init mutex.\n", DRIVER_NAME);
        goto free;
    }
    
    if ((err = init_kmod(ki)) != KERN_SUCCESS) {
        goto free;
    }
    
    mach_vm_address_t kdp_raise_exception_addr = KDP_RAISE_EXCEPTION + kinfo->kaslr_slide;
    // Calculate the size of instructions we need to copy.
    unsigned int size = calculate_instruction_size((void*)kdp_raise_exception_addr);
#if HOOK_KDP_RAISE_EXCEPTION
    // Store our handler and the address of the next instruction to which our handler will
    // jump back, as well as the size of copied instructions for recovery.
    jmp_to_kdp_raise_exception_handler = (uint64_t) kdp_raise_exception_handler;
    jmp_back_to_kdp_raise_exception = kdp_raise_exception_addr + size;
    kdp_raise_exception_patch_size = size;
    if ((err = install_inline_hook((void*)kdp_raise_exception_addr,
                                   size,
                                   kdp_raise_exception_trampoline,
                                   (char*)kdp_raise_exception_trampoline + OFFSET_OF_PLACEHOLDER_IN_TRAMPOLINE,
                                   kdp_raise_exception_inline,
                                   sizeof(kdp_raise_exception_inline))) !=
        KERN_SUCCESS) {
        printf("Faield to hook kdp_raise_exception");
        goto free;
    }
#else
    if ((err = install_inline_hook((void *)kdp_raise_exception_addr,
                                   size,
                                   kdp_raise_exception_handler,
                                   kdp_raise_exception_origin_bytes,
                                   kdp_raise_exception_inline,
                                   sizeof(kdp_raise_exception_inline))) !=
        KERN_SUCCESS) {
        printf("Failed to replace kdp_raise_exception\n");
        goto free;
    }
#endif
    enable_kdp_raise_exception = true;
    
    if ((err = load_breakpoints()) != KERN_SUCCESS) {
        goto unhook;
    }
    
    // Hook other functions
    return KERN_SUCCESS;

unhook:
    unhook_kdp_raise_exception(kinfo);
free:
    uninit_kmod();
    free_mutex();
    return err;
}

kern_return_t
hook_stop(struct kernel_info *kinfo)
{
    unhook_kdp_raise_exception(kinfo);
    // unregister breakpoints and free kext info
    uninit_kmod();
    // release mutex
    free_mutex();
    return KERN_SUCCESS;
}
