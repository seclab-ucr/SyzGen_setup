//
//  client.c
//  hook
//
//  Created by Weiteng Chen on 6/9/20.
//  Copyright © 2020 wchen130. All rights reserved.
//

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

#ifndef LOG_PATH
#define LOG_PATH "/tmp/kernel_hook.txt"
#endif
const char* log_path = LOG_PATH;

void record_mode(int fd, int pid) {
    Entry entries[256];
    while (1) {
        unsigned int len = 256 * sizeof(Entry);
        // Enable Hooker
        if (setsockopt(fd, SYSPROTO_CONTROL, SOCKOPT_SET_ENABLE, &pid, sizeof(pid))) {
            printf("failed to enable!\n");
        }
        
        char c = getc(stdin);
        if (c == EOF) {
            break;
        }
        getc(stdin); // read '\n'
        
        // Disable Hooker
        if (setsockopt(fd, SYSPROTO_CONTROL, SOCKOPT_SET_DISABLE, NULL, 0)) {
            printf("failed to diable!\n");
        }
        
        if (getsockopt(fd, SYSPROTO_CONTROL, SOCKOPT_GET_READ, entries, &len)) {
            printf("failed to get hook data!\n");
        } else {
            FILE *fp = fopen(log_path, "a");
            size_t i = 0;
            for ( ; i < len / sizeof(Entry); i++) {
                printf("port: %lu, selector: %d, id: %d\n",
                       entries[i].connection, entries[i].selector, entries[i].index);
                fprintf(fp, "{\"port\": %llu, \"selector\": %d, \"id\": %d}\n",
                        (uint64_t)entries[i].connection, entries[i].selector, entries[i].index);
            }
            if (i == 256) {
                printf("Reach the max capability, please reduce the number of syscall!\n");
            }
            fclose(fp);
        }
    }
}

void toList(FILE* fp, uint8_t* data, unsigned size) {
    fprintf(fp, "[");
    for (unsigned i = 0; i < size; i++) {
        if (i == 0)
            fprintf(fp, "%u", data[i]);
        else
            fprintf(fp, ", %u", data[i]);
    }
    fprintf(fp, "]");
}

void listen_mode(int fd, int pid) {
    if (setsockopt(fd, SYSPROTO_CONTROL, SOCKOPT_SET_LISTEN, &pid, sizeof(pid))) {
        printf("failed to enable!\n");
        return;
    }
    printf("set listen mode\n");
    printf("output file: /tmp/kernel_hook.txt\n");
    
    char buf[5012];
    while (1) {
        CMD_HEADER* head = (CMD_HEADER*)buf;
        int n = recv(fd, head, sizeof(CMD_HEADER), MSG_WAITALL);
        if (n != sizeof(CMD_HEADER)) {
            printf("recv head failed\n");
            break;
        }
        
        printf("receive head size: %zu, type: %d\n", head->size, head->type);
        n = recv(fd, buf+sizeof(CMD_HEADER), head->size, MSG_WAITALL);
        if (n != head->size) {
            printf("recv %d, expect %zu\n", n, head->size);
            break;
        }

        FILE *fp = fopen(log_path, "a");
        switch (head->type) {
            case HOOK_PRE_EXTERNALMETHOD: {
                CMD_PRE_EXTERNALMETHOD* cmd = (CMD_PRE_EXTERNALMETHOD*)buf;
                printf("port: %lu, selector: %u, inputStructSize: %zu, outputStructSize: %zu, scalarInputCnt: %u, sclarOutputCnt: %u\n",
                       cmd->connection, cmd->selector, cmd->inputStructSize, cmd->outputStructSize, cmd->scalarInputCount, cmd->scalarOutputCount);
                fprintf(fp, "{\"port\": %lu, \"selector\": %u, \"inputStructSize\": %zu, \"outputStructSize\": %zu, \"pid\": %d, \"inputStruct\": ",
                        cmd->connection, cmd->selector, cmd->inputStructSize, cmd->outputStructSize, cmd->header.pid);
                toList(fp, cmd->data, cmd->inputStructSize);
                fprintf(fp, ", \"scalarInputCnt\": %u, \"scalarOutputCnt\": %u, \"scalarInput\": ", cmd->scalarInputCount, cmd->scalarOutputCount);
                toList(fp, (uint8_t*)&cmd->scalarInput[0], cmd->scalarInputCount*sizeof(uint64_t));
                fprintf(fp, "}\n");
                break;
            }
            case HOOK_POST_EXTERNALMETHOD: {
                CMD_POST_EXTERNALMETHOD* cmd = (CMD_POST_EXTERNALMETHOD*)buf;
                printf("outputStructSize: %zu, scalarOutputCount: %u\n", cmd->outputStructSize, cmd->scalarOutputCount);
                fprintf(fp, "{\"outputStructSize\": %zu, \"pid\": %d, \"outputStruct\": ", cmd->outputStructSize, cmd->header.pid);
                toList(fp, cmd->data, cmd->outputStructSize);
                fprintf(fp, ", \"scalarOutputCount\": %u, \"scalarOutput\": ", cmd->scalarOutputCount);
                toList(fp, (uint8_t*)&cmd->scalarOutput[0], cmd->scalarOutputCount*sizeof(uint64_t));
                fprintf(fp, "}\n");
                break;
            }
            case HOOK_WITHADDRESSRANGE: {
                CMD_WITHADDRESSRANGE* cmd = (CMD_WITHADDRESSRANGE*)buf;
                printf("addr: %lu, size: %zu\n", cmd->addr, cmd->size);
                fprintf(fp, "{\"addr\": %lu, \"size\": %zu, \"pid\": %d, \"data\": ", cmd->addr, cmd->size, cmd->header.pid);
                toList(fp, cmd->data, cmd->size);
                fprintf(fp, "}\n");
                break;
            }
            default:
                printf("unknown type: %d\n", head->type);
                break;
        }
        fclose(fp);
    }
}

int main() {
    struct sockaddr_ctl addr;
    bzero(&addr, sizeof(addr));
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    
    int fd = socket(PF_SYSTEM, SOCK_STREAM, SYSPROTO_CONTROL);
    if (fd == -1) {
        perror("Error with socket\n");
        exit(-1);
    }
    
    struct ctl_info info;
    bzero(&info, sizeof(info));
    strncpy(info.ctl_name, HOOK_CTL_NAME, sizeof(info.ctl_name));
    if (ioctl(fd, CTLIOCGINFO, &info)) {
        perror("Could not get ID for kernel control.\n");
        exit(-1);
    }
    addr.sc_id = info.ctl_id;
    addr.sc_unit = 0;
    
    int rc = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (rc) {
        printf("connect failed %d\n", rc);
        perror("connect faield\n");
        exit(-1);
    }
    
//    uint64_t funcs[0xd5];
//    unsigned int len = 0xd5 * sizeof(uint64_t);
//    rc = getsockopt(fd, SYSPROTO_CONTROL, SOCKOPT_GET_TEST, funcs, &len);
//    if (rc == 0) {
//        for (int i = 0; i < 0xd5; i++) {
//            printf("%d: 0x%llx\n", i, funcs[i]);
//        }
//    }
    
//    char buffer[0x100];
//    if (send(fd, buffer, 0x10, 0) == -1) {
//        perror("fail to send\n");
//    }
//    listen_mode(fd, 142);
    listen_mode(fd, 0);
    
    setsockopt(fd, SYSPROTO_CONTROL, SOCKOPT_SET_DISABLE, NULL, 0);
    shutdown(fd, SHUT_RDWR);
    return 0;
}
