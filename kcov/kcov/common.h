//
//  common.h
//  kcov
//
//  Created by Weiteng Chen on 12/23/20.
//  Copyright © 2020 wchen130. All rights reserved.
//

#ifndef common_h
#define common_h

#define DRIVER_NAME "kcov"
#define DRIVER_CTL_NAME "com.wchen130.kcov"
// location of kernel in filesystem
#define MACH_KERNEL "/System/Library/Kernels/kernel.development"
#define KCOV_FILE "/tmp/kcov"

#define DO_LOG 1

// Opcode for getopt
#define SOCKOPT_GET_TEST 1
#define SOCKOPT_GET_BP   2

#define SOCKOPT_SET_ENABLE  1
#define SOCKOPT_SET_DISABLE 2

#define COVER_SIZE (256 << 10)

#endif /* common_h */
