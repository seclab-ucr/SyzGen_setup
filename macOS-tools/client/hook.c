
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/kern_event.h>

#include "../hook/common.h"

#define EXPORT __attribute__((visibility("default")))

static int fd = -1;
static char buffer[512];

EXPORT
int init() {
    struct sockaddr_ctl addr;
    bzero(&addr, sizeof(addr));
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    
    fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd == -1) {
        perror("Error with socket\n");
        return 1;
    }
    
    struct ctl_info info;
    bzero(&info, sizeof(info));
    strncpy(info.ctl_name, HOOK_CTL_NAME, sizeof(info.ctl_name));
    if (ioctl(fd, CTLIOCGINFO, &info)) {
        perror("Could not get ID for kernel control.\n");
        return 2;
    }
    addr.sc_id = info.ctl_id;
    addr.sc_unit = 0;
    
    int rc = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (rc) {
        printf("connect failed %d\n", rc);
        return 3;
    }
    
    return 0;
}

EXPORT
int enable() {
    // Enable Hooker
    if (setsockopt(fd, SYSPROTO_CONTROL, SOCKOPT_SET_ENABLE, NULL, 0)) {
        printf("failed to enable!\n");
        return 1;
    }
    return 0;
}

#define MAX_NUM  32

EXPORT
char* collect(int pid) {
    Entry entries[MAX_NUM];
    unsigned int len = MAX_NUM * sizeof(Entry);
    
    // Disable Hooker
    if (setsockopt(fd, SYSPROTO_CONTROL, SOCKOPT_SET_DISABLE, NULL, 0)) {
        printf("failed to diable!\n");
        return NULL;
    }
    
    if (getsockopt(fd, SYSPROTO_CONTROL, SOCKOPT_GET_READ, entries, &len)) {
        printf("failed to get hook data!\n");
        return NULL;
    } else {
        size_t i = 0;
        for ( ; i < len / sizeof(Entry); i++) {
            // TODO: we also need to match port number
            if (entries[i].pid != pid)
                continue;
            
            // Only return the last one
            char* buf = buffer;
            int size = 512;
            int n = snprintf(buf, size, "{\"port\": %llu, \"selector\": %d, \"inputStructCnt\": %lu, \"outputStructCnt\": %lu, \"id\": %d, \"pid\": %d, \"ptrs\": [",
                     (uint64_t)entries[i].connection, entries[i].selector, entries[i].inputStructCnt,
                     entries[i].outputStructCnt, entries[i].index, entries[i].pid);
            if (n < 0 || n >= size) {
                printf("snprintf error\n");
                return NULL;
            }
            buf += n;
            size -= n;
            
            for (unsigned int j = 0; j < entries[i].num_ptr; j++) {
                if (j == 0)
                    n = snprintf(buf, size, "%llu", entries[i].ptrs[j]);
                else
                    n = snprintf(buf, size, ", %llu", entries[i].ptrs[j]);
                if (n < 0 || n >= size) {
                    printf("snprintf error\n");
                    return NULL;
                }
                buf += n;
                size -= n;
            }
            snprintf(buf, size, "]}");
        }
        if (i == MAX_NUM) {
            printf("Reach the max capability, please reduce the number of syscall!\n");
            return NULL;
        }
    }
    return buffer;
}

EXPORT
void disconnect() {
    if (fd == -1)
        return;
    
    setsockopt(fd, SYSPROTO_CONTROL, SOCKOPT_SET_DISABLE, NULL, 0);
    shutdown(fd, SHUT_RDWR);
}
