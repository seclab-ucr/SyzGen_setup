
import re
import pexpect
import os
import struct

import xml.etree.ElementTree as ET

from ..utils import demangle

SIGEXP = re.compile(r'^((?P<metaClass>[\w:]+)::)?(?P<funcName>~?\w+)\(')
def parse_signature(name):
    # print(name)
    m = SIGEXP.search(str(name).strip())
    if m:
        return m.group("metaClass"), m.group("funcName")
    return None, None
    
class DbgHelper:
    def __init__(self, binary):
        self.binary = binary

    def run(self, cmds):
        print(cmds)
        try:
            lldb = pexpect.spawn("lldb %s" % self.binary)
            lldb.expect("lldb")
            lldb.expect("lldb")
            for cmd in cmds:
                lldb.sendline(cmd)
                lldb.expect("lldb")
                lldb.expect("lldb")
            outs = lldb.before
            return outs
        except pexpect.TIMEOUT:
            pass
        finally:
            lldb.close()

    def getFuncSize(self, proj, funcName, addr):
        name = demangle(funcName)
        metaClass, funcName = parse_signature(name)
        cmds = ["disassemble -n %s::%s" % (metaClass, funcName)]
        lines = self.run(cmds)
        regexp = re.compile(r'\[0x[0-9a-f]+\] \<\+(\d+)\>')
        last = None
        for line in reversed(lines.decode().split("\r\n")):
            m = regexp.search(line)
            if m:
                last = int(m.group(1))
                break

        if last is None:
            raise Exception("failed to disassemble the function")
        block = proj.factory.block(addr+last)
        if len(block.capstone.insns) == 0:
            return last
        return last+block.capstone.insns[0].size

MH_MAGIC = 0xfeedface
MH_MAGIC_64 = 0xfeedfacf
def isMacho(filepath):
    with open(filepath, "rb") as f:
        magic = struct.unpack("I", f.read(4))[0]
        return magic == MH_MAGIC_64

def getBundleIdentifier(path):
    tree = ET.parse(path)
    root = tree.getroot()
    info = root[0]
    size = len(info)
    i = 0
    while i < size:
        node = info[i]
        if node.tag == "key":
            if node.text == "CFBundleIdentifier":
                value = info[i+1]
                return value.text
            i += 2
        else:
            i += 1
    return None

def getInfo2(path):
    plist = os.path.join(path, "Info.plist")
    if not os.path.exists(plist):
        return None, None

    identifier = getBundleIdentifier(plist)
    for name in os.listdir(path):
        _, ext = os.path.splitext(name)
        filepath = os.path.join(path, name)
        if ext == "" and not os.path.isdir(filepath) and isMacho(filepath):
            return identifier, filepath
    return None, None

def getInfo(path):
    plist = os.path.join(path, "Contents", "Info.plist")
    kext = os.path.join(path, "Contents", "MacOS")
    if not os.path.exists(kext):
        # Try the other structure
        return getInfo2(path)

    identifier = getBundleIdentifier(plist)
    for name in os.listdir(kext):
        _, ext = os.path.splitext(name)
        filepath = os.path.join(kext, name)
        if ext == "" and not os.path.isdir(filepath) and isMacho(filepath):
            return identifier, filepath
    return None, None

BlackList = [
    "com.apple.iokit.IOSurface",  # frequently triggerred
    "com.apple.driver.AGPM" # unable to parse the driver
]

def iterate_kext(path, func, debug=True):
    for name in os.listdir(path):
        identifier, binary = getInfo(os.path.join(path, name))
        if identifier and identifier not in BlackList:
            if debug:
                print(binary, identifier)
            if func(binary, identifier):
                return True

        plugins = os.path.join(path, name, "Contents", "Plugins")
        if os.path.exists(plugins):
            if iterate_kext(plugins, func, debug=debug):
                return True

    return False
