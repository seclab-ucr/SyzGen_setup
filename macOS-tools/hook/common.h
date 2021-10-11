//
//  common.h
//  hook
//
//  Created by Weiteng Chen on 6/30/20.
//  Copyright © 2020 wchen130. All rights reserved.
//

#ifndef common_h
#define common_h

#define HOOK_CTL_NAME   "com.wchen130.hook"

#define MAX_ENTRY  256

typedef struct {
    // externalMethod
    long      connection;
    uint32_t  selector;
    // function
    uint32_t  index;
} Entry;

Entry entries[MAX_ENTRY];


#define HOOK_PRE_EXTERNALMETHOD    1
#define HOOK_POST_EXTERNALMETHOD   2
#define HOOK_ROUNTINE              3
#define HOOK_WITHADDRESSRANGE      4

typedef struct {
    size_t size;
    unsigned type;
    int pid;
} CMD_HEADER;

typedef struct {
    CMD_HEADER header;
    long       connection;
    uint32_t   selector;
    
    uint32_t   scalarOutputCount;
    size_t     outputStructSize;
    
    uint32_t   scalarInputCount;
    uint64_t   scalarInput[6];
    size_t     inputStructSize;
    uint8_t    data[4096];
} CMD_PRE_EXTERNALMETHOD;

typedef struct {
    CMD_HEADER header;
    uint32_t   scalarOutputCount;
    uint64_t   scalarOutput[8];
    size_t     outputStructSize;
    uint8_t    data[4096];
} CMD_POST_EXTERNALMETHOD;

typedef struct {
    CMD_HEADER header;
    long       addr;
    size_t     size;
    uint8_t    data[4096];
} CMD_WITHADDRESSRANGE;

// Kernel stack size is small, we use global data instead.
// Assume no data race.
CMD_PRE_EXTERNALMETHOD   gPreExternalMethodCmd;
CMD_POST_EXTERNALMETHOD  gPostExternalMethodCmd;
CMD_WITHADDRESSRANGE     gWithAddressRangeCmd;

#define SOCKOPT_SET_ENABLE     1
#define SOCKOPT_SET_DISABLE    2
#define SOCKOPT_SET_RESET      3
#define SOCKOPT_SET_LISTEN     4
#define SOCKOPT_SET_TEST       5

#define SOCKOPT_GET_TEST       1
#define SOCKOPT_GET_READ       2

#define HOOK_MODE_NONE         0
#define HOOK_MODE_RECORD       1
#define HOOK_MODE_LISTEN       2

#endif /* common_h */
