
#include <libkern/OSByteOrder.h>

#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)

#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)

#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)

#include <unistd.h>

#include <pwd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#if SYZ_EXECUTOR || SYZ_NET_INJECTION

#include <fcntl.h>
#include <sys/types.h>

// All patterns are non-expanding given values < MAX_TUN.
#define TUN_IFACE "tap%d"
#define TUN_DEVICE "/dev/tap%d"

#define LOCAL_MAC "aa:aa:aa:aa:aa:aa"
#define REMOTE_MAC "aa:aa:aa:aa:aa:bb"
#define LOCAL_IPV4 "172.20.%d.170"
#define REMOTE_IPV4 "172.20.%d.187"
#define LOCAL_IPV6 "fe80::%02hxaa"
#define REMOTE_IPV6 "fe80::%02hxbb"

#define COMMAND_MAX_LEN 128
#define PATH_PREFIX "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin "
#define PATH_PREFIX_LEN (sizeof(PATH_PREFIX) - 1)

#endif // SYZ_EXECUTOR || SYZ_NET_INJECTION

#if SYZ_EXECUTOR || SYZ_SANDBOX_SETUID || SYZ_SANDBOX_NONE

#include <sys/resource.h>
#include <unistd.h>

static void sandbox_common()
{
	if (setsid() == -1)
		fail("setsid failed");

	// Some minimal sandboxing.
	struct rlimit rlim;
#ifdef GOOS_freebsd
	// Documented bug in OpenBSD.
	// This causes frequent random aborts. Reason unknown.

	// This also causes ENOMEM on NetBSD during early init.
	rlim.rlim_cur = rlim.rlim_max = 128 << 20;
	setrlimit(RLIMIT_AS, &rlim);
#endif
	rlim.rlim_cur = rlim.rlim_max = 8 << 20;
	setrlimit(RLIMIT_MEMLOCK, &rlim);
	rlim.rlim_cur = rlim.rlim_max = 1 << 20;
	setrlimit(RLIMIT_FSIZE, &rlim);
	rlim.rlim_cur = rlim.rlim_max = 1 << 20;
	setrlimit(RLIMIT_STACK, &rlim);
	rlim.rlim_cur = rlim.rlim_max = 0;
	setrlimit(RLIMIT_CORE, &rlim);
	rlim.rlim_cur = rlim.rlim_max = 256; // see kMaxFd
	setrlimit(RLIMIT_NOFILE, &rlim);
}
#endif //  SYZ_EXECUTOR || SYZ_SANDBOX_SETUID || SYZ_SANDBOX_NONE

#if SYZ_EXECUTOR || SYZ_SANDBOX_NONE

static void loop();

static int do_sandbox_none(void)
{
	sandbox_common();
	loop();
	return 0;
}
#endif // SYZ_EXECUTOR || SYZ_SANDBOX_NONE

#if SYZ_EXECUTOR || SYZ_SANDBOX_SETUID

#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

static void loop();

static int wait_for_loop(int pid)
{
	if (pid < 0)
		fail("sandbox fork failed");
	debug("spawned loop pid %d\n", pid);
	int status = 0;
	while (waitpid(-1, &status, WUNTRACED) != pid) {
	}
	return WEXITSTATUS(status);
}

#define SYZ_HAVE_SANDBOX_SETUID 1
static int do_sandbox_setuid(void)
{
	int pid = fork();
	if (pid != 0)
		return wait_for_loop(pid);

	sandbox_common();

	char pwbuf[1024];
	struct passwd *pw, pwres;
	if (getpwnam_r("nobody", &pwres, pwbuf, sizeof(pwbuf), &pw) != 0 || !pw)
		fail("getpwnam_r(\"nobody\") failed");

	if (setgroups(0, NULL))
		fail("failed to setgroups");
	if (setgid(pw->pw_gid))
		fail("failed to setgid");
	if (setuid(pw->pw_uid))
		fail("failed to setuid");

	loop();
	doexit(1);
}
#endif // SYZ_EXECUTOR || SYZ_SANDBOX_SETUID


#if SYZ_EXECUTOR

#include <IOKit/IOKitLib.h>
#include <mach/mach.h>

struct async_reference {
	mach_port_t port;
	void(*fptr)(void);
	uint64_t something;
};

static long syz_IOServiceOpen(volatile long name, volatile int typ, volatile long port) {
	const char* service_name = (const char*)name;
	io_connect_t* port_ptr = (io_connect_t*)port;
	if (service_name == NULL || port_ptr == NULL)
		return -1;

	io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault,
				IOServiceMatching(service_name));
	if (!service) {
		return -1;
	}
	kern_return_t kr = IOServiceOpen(service, mach_task_self(), typ, port_ptr);
	IOObjectRelease(service);
	if (kr != kIOReturnSuccess) {
		return kr;
	}
	return 0;
}

static long syz_IOServiceClose(volatile long arg) {
	io_connect_t port = (io_connect_t)arg;
	return IOServiceClose(port);
}

static long syz_IOConnectCallMethod(volatile long arg0, volatile long arg1, volatile long arg2, volatile long arg3,
		volatile long arg4, volatile long arg5, volatile long arg6, volatile long arg7, volatile long arg8,
		volatile long arg9) {
	return IOConnectCallMethod((mach_port_t) arg0, (uint32_t) arg1,
		(const uint64_t *) arg2, (uint32_t) arg3,
		(const void *) arg4, (size_t) arg5,
		(uint64_t *) arg6, (uint32_t *) arg7,
		(void *) arg8, (size_t*) arg9
		);
}

static long syz_IOConnectCallAsyncMethod(volatile long arg0, volatile long arg1, volatile long arg2, volatile long arg3,
		volatile long arg4, volatile long arg5, volatile long arg6, volatile long arg7, volatile long arg8,
		volatile long arg9) {

	mach_port_t p = MACH_PORT_NULL;
	mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p);
	mach_port_insert_right(mach_task_self(), p, p, MACH_MSG_TYPE_MAKE_SEND);

	struct async_reference async_ref = {0};
	async_ref.port = p;

	return IOConnectCallAsyncMethod((mach_port_t) arg0, (uint32_t) arg1,
		p, (uint64_t*)&async_ref, 1,
		(const uint64_t *) arg2, (uint32_t) arg3,
		(const void *) arg4, (size_t) arg5,
		(uint64_t *) arg6, (uint32_t *) arg7,
		(void *) arg8, (size_t*) arg9
		);
}
#endif
