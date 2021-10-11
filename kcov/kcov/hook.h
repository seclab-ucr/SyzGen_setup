//
//  hook.h
//  kcov
//
//  Created by Weiteng Chen on 12/24/20.
//  Copyright © 2020 wchen130. All rights reserved.
//

#ifndef hook_h
#define hook_h

#include "kernel_info.h"

kern_return_t hook_start(kmod_info_t *ki, struct kernel_info *kinfo);
kern_return_t hook_stop(struct kernel_info *kinfo);

/*
 * Procedure to call hooked functions
 * 1. save registers before calling our handler
 * 2. call our handler
 * 3. restore registers
 * 4. placeholder for the first few instructions from the hooked function
 * that are patched to jump to this trampoline. We execute these missing
 * instructions and then come back to the remaining instructions in the
 * hooked function.
 */
// FIXME: I think we do not need to save registers.
#define OFFSET_OF_PLACEHOLDER_IN_TRAMPOLINE 54
#define SIZE_OF_PLACEHOLDER_IN_TRAMPOLINE   20
#define Trampoline(name, handlerAddr, retAddr)      \
__attribute__ ((naked))                             \
void                                                \
name##_trampoline()                                 \
{                                                   \
    __asm__ volatile ("pushfq");                    \
    __asm__ volatile ("push %rax");                 \
    __asm__ volatile ("push %rbx");                 \
    __asm__ volatile ("push %rcx");                 \
    __asm__ volatile ("push %rdx");                 \
    __asm__ volatile ("push %rbp");                 \
    __asm__ volatile ("push %rsi");                 \
    __asm__ volatile ("push %rdi");                 \
    __asm__ volatile ("push %r8");                  \
    __asm__ volatile ("push %r9");                  \
    __asm__ volatile ("push %r10");                 \
    __asm__ volatile ("push %r11");                 \
    __asm__ volatile ("push %r12");                 \
    __asm__ volatile ("push %r13");                 \
    __asm__ volatile ("push %r14");                 \
    __asm__ volatile ("push %r15");                 \
    __asm__ volatile ("call *%0\n"                  \
                      :                             \
                      : "m" (handlerAddr));         \
    __asm__ volatile ("pop %r15");                  \
    __asm__ volatile ("pop %r14");                  \
    __asm__ volatile ("pop %r13");                  \
    __asm__ volatile ("pop %r12");                  \
    __asm__ volatile ("pop %r11");                  \
    __asm__ volatile ("pop %r10");                  \
    __asm__ volatile ("pop %r9");                   \
    __asm__ volatile ("pop %r8");                   \
    __asm__ volatile ("pop %rdi");                  \
    __asm__ volatile ("pop %rsi");                  \
    __asm__ volatile ("pop %rbp");                  \
    __asm__ volatile ("pop %rdx");                  \
    __asm__ volatile ("pop %rcx");                  \
    __asm__ volatile ("pop %rbx");                  \
    __asm__ volatile ("pop %rax");                  \
    __asm__ volatile ("popfq");                     \
                                                    \
    __asm__ volatile ("nop"); /* Placeholder */     \
    __asm__ volatile ("nop");                       \
    __asm__ volatile ("nop");                       \
    __asm__ volatile ("nop");                       \
    __asm__ volatile ("nop");                       \
    __asm__ volatile ("nop");                       \
    __asm__ volatile ("nop");                       \
    __asm__ volatile ("nop");                       \
    __asm__ volatile ("nop");                       \
    __asm__ volatile ("nop");                       \
    __asm__ volatile ("nop");                       \
    __asm__ volatile ("nop");                       \
    __asm__ volatile ("nop");                       \
    __asm__ volatile ("nop");                       \
    __asm__ volatile ("nop");                       \
    __asm__ volatile ("nop");                       \
    __asm__ volatile ("nop");                       \
    __asm__ volatile ("nop");                       \
    __asm__ volatile ("nop");                       \
    __asm__ volatile ("nop");                       \
    __asm__ volatile ("jmp *%0\n"                   \
                      :                             \
                      : "m" (retAddr));             \
    __asm__ volatile ("int3");                      \
}

//
// 48 b8 00 00 00 00 00 00 00 00   movabsq $0x0, %rax
// ff e0                           jmpq   *%rax
//

#define Inlined_code(name)            \
static char name##_inline[12] =             \
"\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00"  \
"\xff\xe0"

#endif /* hook_h */
