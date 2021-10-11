#include <IOKit/IOKitLib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

static long syz_IOServiceOpen(char *service_name, io_connect_t *port_ptr, int type)
{
  io_service_t service = IOServiceGetMatchingService(
      kIOMasterPortDefault, IOServiceMatching(service_name));
  if (!service) {
    return -1;
  }
  kern_return_t kr = IOServiceOpen(service, mach_task_self(), type, port_ptr);
  IOObjectRelease(service);
  if (kr != kIOReturnSuccess) {
    return -2;
  }
  return 0;
}

static long syz_IOServiceClose(volatile long arg)
{
  io_connect_t port = (io_connect_t)arg;
  return IOServiceClose(port);
}

int main(int argc, char **argv) {
  if (argc <= 2)
    return 1;

  printf("service name: %s\n", argv[1]);
  printf("type: %d\n", atoi(argv[2]));
  io_service_t connection;
  long ret = syz_IOServiceOpen(argv[1], &connection, atoi(argv[2]));
  if (ret == -1) {
    printf("failed to open service!\n");
    return ret;
  } else if (ret == -2) {
    printf("failed to open connection!\n");
    return -2;
  }
  printf("succeed!!\n");
  syz_IOServiceClose(connection);
  return 0;
}

