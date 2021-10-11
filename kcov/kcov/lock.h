//
//  lock.h
//  kcov
//
//  Created by 陈伟腾 on 12/26/20.
//  Copyright © 2020 wchen130. All rights reserved.
//

#ifndef lock_h
#define lock_h

//
// Enable and disable interrupts
//
#define disable_interrupts() __asm__ volatile ("cli");
#define enable_interrupts() __asm__ volatile ("sti");

void disable_write_protection(void);
void enable_write_protection(void);
void disable_write_protection_without_lock(void);
void enable_write_protection_without_lock(void);

kern_return_t init_mutex(void);
void free_mutex(void);

#endif /* lock_h */
