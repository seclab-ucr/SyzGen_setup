
import sys
import re

def main(filepath):
    syscalls = []
    with open(filepath, "r") as fp:
        for line in fp:
            m = re.search(r'syz_IOConnectCall(Async)?Method\$.+\(', line)
            if m:
                call = m.group(0)[:-1]
                syscalls.append(call)
    syscalls = sorted(syscalls)
    for syscall in syscalls:
        print("    \"%s\"," % syscall)

if __name__ == '__main__':
    sys.exit(main(sys.argv[1]))
