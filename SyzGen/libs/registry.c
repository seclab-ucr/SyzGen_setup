
#include <stdio.h>
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>

int main(int argc, char **argv) {
  if (argc <= 2)
    return 1;

  // printf("service name: %s\n", argv[1]);
  io_service_t service = IOServiceGetMatchingService(
    kIOMasterPortDefault, IOServiceMatching(argv[1]));
  if (!service) {
    printf("failed to get service\n");
    return -1;
  }
  
  CFStringRef key = CFStringCreateWithCString(kCFAllocatorDefault, argv[2], kCFStringEncodingUTF8);
  CFTypeRef userClient = IORegistryEntryCreateCFProperty(service, 
    key, kCFAllocatorDefault, 0);
  if (userClient) {
    CFShow(userClient);
  } else {
    CFRelease(key);
    printf("user client is NULL\n");
    return -2;
  }

  if (userClient != NULL)
    CFRelease(userClient);
  CFRelease(key);
  IOObjectRelease(service);
  return 0;
}