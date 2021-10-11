#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/kern_control.h>
#include <sys/kern_event.h>

static void os_init(int argc, char** argv, void* data, size_t data_size)
{
	int prot = PROT_READ | PROT_WRITE | PROT_EXEC;

	if (mmap(data, data_size, prot, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0) != data)
		fail("mmap of data segment failed");

	// Makes sure the file descriptor limit is sufficient to map control pipes.
	struct rlimit rlim;
	rlim.rlim_cur = rlim.rlim_max = kMaxFd;
	setrlimit(RLIMIT_NOFILE, &rlim);
}

static intptr_t execute_syscall(const call_t* c, intptr_t a[kMaxArgs])
{
	return c->call(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9]);
}

#define KCOV_CTL_NAME   "com.wchen130.kcov"

#define SOCKOPT_SET_ENABLE     1
#define SOCKOPT_SET_DISABLE    2
#define SOCKOPT_SET_RESET      3

#define SOCKOPT_GET_TEST       1
#define SOCKOPT_GET_READ       2

#define MAX_ENTRY  64

static void hook_open(hook_t *hook) {	
	struct sockaddr_ctl addr;
    bzero(&addr, sizeof(addr));
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    
    int fd = socket(PF_SYSTEM, SOCK_STREAM, SYSPROTO_CONTROL);
    if (fd == -1) {
        fail("Error with socket");
    }
    if (dup2(fd, hook->fd) < 0)
		fail("filed to dup2(%d, %d) cover fd", fd, hook->fd);
	close(fd);
    
    struct ctl_info info;
    bzero(&info, sizeof(info));
    strncpy(info.ctl_name, KCOV_CTL_NAME, sizeof(info.ctl_name));
    if (ioctl(hook->fd, CTLIOCGINFO, &info)) {
        fail("Could not get ID for kernel control.");
    }
    addr.sc_id = info.ctl_id;
    addr.sc_unit = 0;
    
    int rc = connect(hook->fd, (struct sockaddr*)&addr, sizeof(addr));
    if (rc) {
        fail("connect failed %d", rc);
    }

    hook->data = (char*)malloc(kCoverSize);
    if (hook->data == NULL)
        fail("malloc data failed");
}

static void hook_enable(hook_t *hook) {
	if (setsockopt(hook->fd, SYSPROTO_CONTROL, SOCKOPT_SET_ENABLE, NULL, 0)) {
        fail("failed to enable!");
    }
}

static void hook_collect(hook_t *hook) {
    uint64_t cmd = 0;
    uint64_t num = 0;
    // If the data is not aligned with 8, somehow there seems to be some padding data left in the queue.
    int n = send(hook->fd, &cmd, sizeof(cmd), MSG_WAITALL);
    n = recv(hook->fd, &num, sizeof(cmd), MSG_WAITALL);
    // printf("number of pc: %llu\n", num);
    // avoid overflow
    if (num > kCoverSize/sizeof(uint64_t))
        num = kCoverSize/sizeof(uint64_t);
    if (num) {
        n = recv(hook->fd, hook->data, num * sizeof(uint64_t), MSG_WAITALL);
        if (n != num * sizeof(uint64_t)) {
            fail("recv %d, expect %llu", n, num * sizeof(uint64_t));
        }
        hook->size = n / sizeof(uint64_t);
        // uint64_t *data = (uint64_t *)hook->data;
        // for (unsigned i = 0; i < num; i++) {
        //     printf("cov: 0x%llx\n", data[i]);
        // }
    } else {
        hook->size = 0;
    }
}

#include "nocover.h"
