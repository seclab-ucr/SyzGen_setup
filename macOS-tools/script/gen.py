
import os
import argparse
import re
import subprocess

import angr

template = """
//
//  gen.h: It should be auto-generated.
//  hook
//
//  Created by Weiteng Chen on 6/10/20.
//  Copyright @ 2020 wchen130. All rights reserved.
//

#ifndef gen_h
#define gen_h

#define TARGET_KEXT  "%s"
#define EXTERNALMETHOD_OFFSET  0x%x

uint32_t Offset2WithAddressRange[] = {
    %s
};


#endif /* gen_h */

"""

def check_output(cmds):
    ret = subprocess.run(cmds, check=True, cwd=os.getcwd(), stdout=subprocess.PIPE)
    return ret.stdout

def demangle(name):
    # https://github.com/nico/demumble
    output = check_output(["./demumble", name])
    return output.decode().strip()

SIGEXP = re.compile(r'^((?P<metaClass>[\w:]+)::)?(?P<funcName>~?\w+)\(')
def parse_signature(name):
    # print(name)
    m = SIGEXP.search(str(name).strip())
    if m:
        return m.group("metaClass"), m.group("funcName")
    return None, None

def find(proj, addr):
    for sym in proj.loader.main_object.symbols:
        if sym.relative_addr == addr and sym.name:
            return sym
    return None

def findVtable(proj, clazz):
    for sym in proj.loader.main_object.symbols:
        if sym.name.startswith("__ZTV"):
            demangledname = demangle(sym.name).strip()
            if demangledname.startswith("vtable for "):
                metaClass = demangledname[len("vtable for "):]
                if sym.value != 0 and metaClass == clazz:
                    return sym
    return None

def findFunCall(proj, func):
    ret = []
    for addr, rel in proj.loader.main_object.extreltab.items():
        idx = rel.referenced_symbol_index
        sym = proj.loader.main_object.get_symbol_by_insertion_order(idx)
        if func != sym.name:
            continue

        print(sym.name)
        print(hex(rel.addr))
        ret.append(rel.addr)
    return ret

def main(binary, clazz, kext):
    proj = angr.Project(binary)
    vtable = findVtable(proj, clazz)
    EXTERNALMETHOD_OFFSET = 0
    if vtable:
        addr = vtable.value+0x10
        with open(binary, "rb") as fp:
            end = addr
            while True:
                if end not in proj.loader.main_object.extreltab:
                    offset = proj.loader.main_object._unpack("Q", fp, end, 8)[0]
                    if offset == 0:
                        break
                    sym = find(proj, offset)
                    name, func = parse_signature(demangle(sym.name))
                    if func == "externalMethod":
                        EXTERNALMETHOD_OFFSET = end
                        break
                end += 8
    else:
        print("failed to find the vtable for %s" % clazz)

    print("externalMethod: 0x%x" % EXTERNALMETHOD_OFFSET)
    withAddressRanges = findFunCall(proj, "__ZN18IOMemoryDescriptor16withAddressRangeEyyjP4task")
    out = template % (kext, EXTERNALMETHOD_OFFSET, ",\n    ".join([hex(each) for each in withAddressRanges]))
    print(out)

    with open("../hook/gen.h", "w") as fp:
        fp.write(out)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '--binary', help="path to the binary")
    parser.add_argument('--clazz', help="clazz name")
    parser.add_argument('--kext', help="bundle id")

    args = parser.parse_args()
    if args.binary and args.clazz and args.kext:
        main(args.binary, args.clazz, args.kext)
