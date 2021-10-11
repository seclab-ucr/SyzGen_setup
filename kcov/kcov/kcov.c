//
//  kcov.c
//  kcov
//
//  Created by Weiteng Chen on 12/19/20.
//  Copyright © 2020 wchen130. All rights reserved.
//

#include <sys/systm.h>
#include <mach/mach_types.h>
#include <os/log.h>
#include <sys/fcntl.h>
#include <sys/proc.h>
#include <kern/locks.h>
#include <i386/proc_reg.h>
#include <IOKit/IOLib.h>
#include <sys/kern_control.h>
#include <libkern/libkern.h>

#include "common.h"
#include "kernel_info.h"
#include "kdp.h"
#include "hook.h"
#include "gen.h"

kern_ctl_ref gKeCtlRef = NULL;

kern_return_t kcov_start(kmod_info_t * ki, void *d);
kern_return_t kcov_stop(kmod_info_t *ki, void *d);

static
kern_return_t
enable_kcov(
    kcov_t *kcov
    )
{
    if (kcov->area) {
        _FREE(kcov->area, M_TEMP);
        kcov->area = NULL;
    }
    
    kcov->area = _MALLOC(COVER_SIZE, M_TEMP, M_ZERO);
    if (kcov->area == NULL)
        return KERN_NO_SPACE;
    
    // First field is the number of recorded pc.
    kcov->area[0] = 0;
    return KERN_SUCCESS;
}

static
void
disable_kcov(
    kcov_t *kcov
    )
{
    if (kcov && kcov->area) {
        _FREE(kcov->area, M_TEMP);
        kcov->area = NULL;
    }
}

errno_t KcovHandleSetOpt(kern_ctl_ref ctlref, unsigned int unit, void *unitinfo, int opt, void *data, size_t len) {
#if DO_LOG
    printf("[%s.kext] call setOpt %d with unit %d\n", DRIVER_NAME, opt, unit);
#endif
    int error = KERN_INVALID_VALUE;
    switch (opt) {
        case SOCKOPT_SET_ENABLE:
            error = enable_kcov((kcov_t *)unitinfo);
            break;
        case SOCKOPT_SET_DISABLE:
            disable_kcov((kcov_t *)unitinfo);
            return KERN_SUCCESS;
        default:
            break;
    }
    return error;
}

errno_t KcovHandleGetOpt(kern_ctl_ref ctlref, unsigned int unit, void *unitinfo, int opt, void *data, size_t *len) {
#if DO_LOG
    printf("[%s.kext] call getOpt %d with unit %d\n", DRIVER_NAME, opt, unit);
#endif
    int error = EINVAL;
    switch (opt) {
        case SOCKOPT_GET_TEST:
            test_install_breakpoints(data);
            return KERN_SUCCESS;
        case SOCKOPT_GET_BP:
            show_breakpoints(data, len);
            return KERN_SUCCESS;
        default:
            break;
    }
    return error;
}

errno_t KcovHandleConnect(kern_ctl_ref ctlref, struct sockaddr_ctl *sac, void **unitinfo) {
#if DO_LOG
    printf("[%s.kext] call connect...\n", DRIVER_NAME);
#endif
    for (int i = 0; i < NUM_OF_KCOV; i++) {
        if (gKcov[i] != NULL) {
            continue;
        }
        
        kcov_t *kcov = _MALLOC(sizeof(kcov_t), M_TEMP, M_ZERO);
        kcov->area = NULL;
//        kcov->enable = false;
        
        gKcov[i] = kcov;
        *unitinfo = kcov;
        return KERN_SUCCESS;
    }
    return KERN_NO_SPACE;
}

errno_t KcovhandleDisconnect(kern_ctl_ref ctlref, unsigned int unit, void *unitinfo) {
#if DO_LOG
    printf("[%s.kext] call disconnect...\n", DRIVER_NAME);
#endif
    kcov_t *kcov = unitinfo;
    for (int i = 0; i < NUM_OF_KCOV; i++) {
        if (gKcov[i] == kcov) {
            gKcov[i] = NULL;
            break;
        }
    }
    
    if (kcov) {
        if (kcov->area) {
            _FREE(kcov->area, M_TEMP);
            kcov->area = NULL;
        }
        _FREE(kcov, M_TEMP);
    }
    return KERN_SUCCESS;
}

errno_t KcovHandleSend(kern_ctl_ref ctlref, unsigned int unit, void *unitinfo, mbuf_t m, int flags) {
    int error = KERN_SUCCESS;
    kcov_t *kcov = unitinfo;
    // release input data (Make sure the input is aligned with 8).
    mbuf_freem(m);
    if (kcov && kcov->area) {
        uint64_t pos = kcov->area[0];
        // TODO: Is it necessary to make sure all data can be sent to user space?
        // The interface is not designed to transfer large amount of data.
        size_t remain = 0;
        if ((error = ctl_getenqueuespace(gKeCtlRef, unit, &remain)) != 0) {
            printf("invalid parameters for getenqueuespace: %d\n", error);
            return error;
        }
        
        if (remain < sizeof(uint64_t)) {
            printf("no space at all\n");
            return KERN_NO_SPACE;
        }
        remain -= sizeof(uint64_t);
        
        if (remain / 8 < pos) {
            printf("remaining space is not enough!\n");
            pos = remain / 8;
        }
        if ((error = ctl_enqueuedata(gKeCtlRef, unit, &pos, sizeof(uint64_t), 0)) != 0) {
            return error;
        }
        if ((error = ctl_enqueuedata(gKeCtlRef, unit, &kcov->area[1], pos*sizeof(uint64_t), 0)) != 0) {
            return error;
        }
    } else {
        printf("kcov is NULL\n");
        uint64_t pos = 0;
        if ((error = ctl_enqueuedata(gKeCtlRef, unit, &pos, sizeof(uint64_t), 0)) != 0) {
            return error;
        }
    }
    return error;
}

/* Register an interface for communication between user application and kernel space. */
kern_return_t
register_kernelCtrl(
    )
{
    struct kern_ctl_reg KeCtlReg = {0};
    bzero(&KeCtlReg, sizeof(struct kern_ctl_reg));
    strncpy(KeCtlReg.ctl_name, DRIVER_CTL_NAME, strlen(DRIVER_CTL_NAME));
    KeCtlReg.ctl_flags      =    CTL_FLAG_REG_SOCK_STREAM;
    KeCtlReg.ctl_setopt     =    KcovHandleSetOpt;
    KeCtlReg.ctl_getopt     =    KcovHandleGetOpt;
    KeCtlReg.ctl_connect    =    KcovHandleConnect;
    KeCtlReg.ctl_disconnect =    KcovhandleDisconnect;
    KeCtlReg.ctl_send       =    KcovHandleSend;
    
    errno_t err = ctl_register(&KeCtlReg, &gKeCtlRef);
    if (err == KERN_SUCCESS) {
        printf("Register KerCtlConnection success: id=%d", KeCtlReg.ctl_id);
    } else {
        printf("Fail to register: err=%d", err);
        return KERN_FAILURE;
    }
    return KERN_SUCCESS;
}

void deregister_kernelCtrl() {
    if (gKeCtlRef == NULL) {
        return;
    }
    
    errno_t err = ctl_deregister(gKeCtlRef);
    if (err) {
        printf("Fail to deregister: err=%d", err);
    }
    gKeCtlRef = NULL;
}

kern_return_t kcov_start(kmod_info_t * ki, void *d)
{
    errno_t err = KERN_SUCCESS;
    printf("[%s.kext] Kernel module is loaded.\n", DRIVER_NAME);
    // register interface
    if ((err = register_kernelCtrl()) != KERN_SUCCESS)
        return err;
    
    // init kernel info before others
    if ((err = init_kernel_info(&g_kernel_info)) != KERN_SUCCESS)
        return err;
    
    // register hooks
    if ((err= hook_start(ki, &g_kernel_info)) != KERN_SUCCESS)
        return err;
    
    return KERN_SUCCESS;
}

kern_return_t kcov_stop(kmod_info_t *ki, void *d)
{
    hook_stop(&g_kernel_info);
    deregister_kernelCtrl();
    return KERN_SUCCESS;
}
