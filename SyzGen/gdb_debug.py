
import gdb
import argparse
import shlex
import json
import struct
import socket
import time

# set pagination off
# source proxy.py
# source gdb_debug.py

def lookup_types(*types):
    for type_str in types:
        try:
            return gdb.lookup_type(type_str)
        except Exception as e:
            exc = e
    raise exc

uint64 = lookup_types('unsigned long long', 'ulong', 'u64', 'uint64')
uint   = lookup_types('unsigned int', 'uint', 'u32', 'uint32')
ushort = lookup_types('unsigned short', 'ushort', 'u16', 'uint16')
uchar  = lookup_types('unsigned char', 'ubyte', 'u8', 'uint8')

class GDBDebugger(object):
    def __init__(self):
        pass

    def read_register(self, register, **kwargs):
        print("read register %s" % register)
        if register == "gs":
            return self.get_gs_register()

        # https://github.com/pwndbg/pwndbg/blob/05036defa01d4d47bfad56867f53470a29fcdc89/pwndbg/regs.py#L284
        val = gdb.selected_frame().read_register(register)
        val = val.cast(uint64)
        return int(val)

    def write_register(self, register, value, **kwargs):
        print("write reigster %s" % register, value)
        if type(value) == str:
            gdb.execute("set $%s = %s" % (register, value))
        elif type(value) == int:
            gdb.execute("set $%s = %d" % (register, value))
        else:
            raise Exception("unknown type %s for value" % type(value))

    def read_memory(self, addr, nbytes, **kwargs):
        result = gdb.selected_inferior().read_memory(addr, nbytes)
        return bytearray(result)

    def write_memory(self, addr, data, *args, **kwargs):
        if isinstance(data, str):
            data = bytes(data, 'utf8')
        
        gdb.selected_inferior().write_memory(addr, data)

    def get_gs_register(self, timeout=5):
        shellcode = b'\x65\x48\x8b\x04\x25\x00\x00\x00\x00' # moveq %gs:0x0, %rax
        orig_rax = self.read_register("rax")
        orig_pc = self.read_register("rip")
        orig_insts = self.read_memory(orig_pc, len(shellcode))
        print("rax: %s, rip: %s" % (orig_rax, orig_pc))
        print(orig_insts)

        self.write_memory(orig_pc, shellcode)

        self.step(timeout=timeout)

        # restore
        self.write_memory(orig_pc, orig_insts)
        self.write_register("rip", orig_pc)

        gs = self.read_register("rax")
        self.write_register("rax", orig_rax)

        return gs

    def step(self, timeout=5):
        gdb.execute("si")

class GDBProxy(gdb.Command, Proxy):
    """GDB Proxy to execute commands from server or local users
    """

    program = "proxy"

    def __init__(self):
        super(GDBProxy, self).__init__("proxy", gdb.COMMAND_USER)
        Proxy.__init__(self)

        self.debugger = GDBDebugger()

        print('The "{0}" command has been installed, type "help {0}" or "{0} -h"'
            ' for detailed help.'.format(self.program))

    def invoke(self, arg, from_tty):
        self.dont_repeat()

        Proxy.call_from_debugger(self, arg)

    def handle_command(self, request):
       cmd = request["cmd"]
       
       return Proxy.handle_command(self, request)

    def test(self):
        print("test")

    @catch_exception
    def read_register(self, request):
        ret = {}
        reg_name = str(request["reg"])
        val = self.debugger.read_register(reg_name)
        ret["val"] = val
        return ret

    @catch_exception
    def read_memory(self, request):
        addr = request["addr"]
        size = request["size"]
        ret = {}

        val = self.debugger.read_memory(addr, size)
        ret["val"] = val
        return ret


GDBProxy()
