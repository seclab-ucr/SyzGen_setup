#! /bin/python3

import angr
import sys
import os

gen = """
#ifndef gen_h
#define gen_h

#define MACH_KERNEL "/System/Library/Kernels/{0}"
#define PANIC_OFFSET {1:#x}
#define KDP_RAISE_EXCEPTION {2:#x} 

#endif
"""

def find_symbol(proj, name):
    for sym in proj.loader.main_object.symbols:
        if name == sym.name:
            return sym
    return None

def main(kernel_path):
    proj = angr.Project(kernel_path, auto_load_libs=False)
    symbols = ["_panic", "_kdp_raise_exception"]
    addrs = []
    for symbol in symbols:
        sym = find_symbol(proj, symbol)
        if sym is None:
            raise Exception("failed to find the address of %s" % symbol)
        addrs.append(sym.relative_addr)

    with open("../kcov/gen.h", "w") as fp:
        fp.write(gen.format(os.path.basename(kernel_path), *addrs))

    print("Successfully generate gen.h")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("usage: python parse.py /path/to/kernel")
        exit(1)
    kernel_path = sys.argv[1]
    if not os.path.exists(kernel_path):
        print("%s does not exit" % kernel_path)
        exit(2)

    exit(main(kernel_path))
