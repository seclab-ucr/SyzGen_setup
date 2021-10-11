
import lldb
import time
import socket
import struct
import json
import argparse
import shlex

#
# sudo dtrace -w -n "BEGIN { breakpoint(); }"
# 

CURRENT_THREAD_ID = 0

def run_cmd(cmd):
    interpreter = lldb.debugger.GetCommandInterpreter()
    res = lldb.SBCommandReturnObject()
    interpreter.HandleCommand(cmd, res)
    if not res.Succeeded():
        raise Exception("failed to run cmd %s" % cmd)
    if res.HasResult():
        return res.GetOutput().strip()
    return ""

def breakpoint_externalMethod(frame, bp_loc, data):
    # global CURRENT_THREAD_ID

    print("breakpoint hit!", frame.GetThread().GetThreadID())
    # if CURRENT_THREAD_ID and frame.GetThread().GetThreadID() != CURRENT_THREAD_ID:
    #     frame.GetThread().GetProcess().Continue()
    #     return

    # output = run_cmd("showtask -F %s" % "poc")
    # for line in output.split("\n")[1:]:
    #     cols = line.split()
    #     # task = int(cols[0], 16)
    #     res = run_cmd("showcurrentthreads -s %s" % cols[0])
    #     if len(res) != 0:  # Other process may also hit this
    #         CURRENT_THREAD_ID = frame.GetThread().GetThreadID()
    #         return
            
    # process = frame.GetThread().GetProcess()
    # process.Continue()
    
def set_thread():
    global CURRENT_THREAD_ID

    CURRENT_THREAD_ID = lldb.thread.GetThreadID()
    print("set thread", CURRENT_THREAD_ID)

def run_async(f):
    def wrapper(*args, **kwargs):
        orig_async = lldb.debugger.GetAsync()
        lldb.debugger.SetAsync(True)
        try:
            ret = f(*args, **kwargs)
            return ret
        finally:
            lldb.debugger.SetAsync(orig_async)
    return wrapper

class LLDBDebugger(object):
    def __init__(self):
        pass
    
    def get_current_thread(self):
        # TODO: GetThreadAtIndex(3)???
        process = lldb.target.GetProcess()
        if process.GetNumThreads() > 1:
            print("More than one thread")
        thread = process.GetThreadAtIndex(0)
        return thread

    def read_register(self, register, **kwargs):
        print("read register %s" % register)
        if register == "gs":
            return self.get_gs_register()
        
        # process = lldb.target.GetProcess()
        # thread = process.GetThreadAtIndex(0)
        thread = self.get_current_thread()
        frame = thread.GetFrameAtIndex(0)
        ret = frame.FindRegister(register)
        if ret is None:
            raise Exception("register %s is None" % register)
        if ret.value is None:
            raise Exception("register %s value is None" % register)
        return ret.value
    
    def read_task(self, name, **kwargs):
        output = run_cmd("showtask -F %s" % name)
        for line in output.split("\n")[1:]:
            cols = line.split()
            return int(cols[0], 16)
        return 0
    
    def read_user_memory(self, task, address, nbytes, **kwargs):
        print("read user memory at 0x%x with %d" % (address, nbytes))
        cmd = "printuserdata 0x%x 0x%x %dB" % (task, address, nbytes)
        output = run_cmd(cmd)
        ret = bytearray()
        for line in output.split("\n"):
            v = int(line.split(":")[1].strip())
            ret.append(v)
        return ret
    
    def read_kext_mapping(self, **kwargs):
        output = run_cmd("showallkexts")
        ret = list()
        for line in output.split("\n")[1:]:
            cols = line.split()
            if len(cols) != 10:
                continue
            addr, size, name = int(cols[2], 16), int(cols[7], 16), cols[9]
            if addr == 0:
                continue
            ret.append((addr, size, name))
        return ret
    
    def read_memory(self, address, nbytes, **kwargs):
        print("read memory at 0x%x with %d" % (address, nbytes))
        error = lldb.SBError()
        process = lldb.target.GetProcess()
        content = process.ReadMemory(address, nbytes, error)
        if error.Success():
            return bytearray(content)
        raise Exception("failed to read memory")
        
    def write_memory(self, address, value, *args, **kwargs):
        print("write memory at 0x%x" % address, value)
        error = lldb.SBError()
        process = lldb.target.GetProcess()
        new_value = str(value)  # FIXME: pthon2 style
        result = process.WriteMemory(address, new_value, error)
        if not error.Success():
            raise Exception("failed to write memory")
        if result != len(value):
            raise Exception("only wrote %d bytes" % result)
            
    def write_register(self, register, value, **kwargs):
        new_value = str(value)  # FIXME: pthon2 style
        print("write register %s with %s" % (register, new_value))
        if register == "pc": register = "rip"

        # process = lldb.target.GetProcess()
        # thread = process.GetThreadAtIndex(0)
        thread = self.get_current_thread()
        frame = thread.GetFrameAtIndex(0)
        reg = frame.register[register]
        if reg is None:
            raise Exception("register %s not available" % register)
        try:
            reg.value = new_value
        except:
            raise Exception("failed to write register")
            
    def get_gs_register(self, timeout=5):
        print("read segment register")
        shellcode = "\x65\x48\x8b\x04\x25\x00\x00\x00\x00" # movq   %gs:0x0, %rax
        orig_rax = self.read_register("rax")
        orig_pc = self.read_register("rip")
        pc = int(orig_pc, 16)
        orig_insts = self.read_memory(pc, len(shellcode))
        print("rax: %s, rip: %s" % (orig_rax, orig_pc))
        print(orig_insts)
        
        self.write_memory(pc, shellcode)
        
        self.step(timeout=timeout)
                
        # restore
        self.write_memory(pc, orig_insts)
        self.write_register("rip", orig_pc)
        
        gs = self.read_register("rax")
        self.write_register("rax", orig_rax)
        return gs
    
    # def find_function_addr(self, name):
    #     print("find start addr for %s" % name)
    #     for each in lldb.target.FindFunctions(name):
    #         addr = each.symbol.addr.load_addr
    #         if addr != 0xffffffffffffffffL:
    #             return addr
    #     raise Exception("Cannot find the symbol %s" % name)

    def find_function_addr(self, name):
        ret = []
        for each in lldb.target.FindFunctions(name):
            if not each.block.IsInlined():
                addr = each.symbol.addr.load_addr
                ret.append({"inlined": False, "addr": addr})
                # print(each.symbol.name, hex(addr))
            else:
                for start, end in each.block.ranges:
                    ret.append({"inlined": True, "start": start.load_addr, "end": end.load_addr})
                    # print("[inlined]", hex(start.load_addr), hex(end.load_addr))
        if len(ret) == 0:
            raise Exception("Cannot find the symbol %s" % name)
        return ret
    
    def find_function_name(self, addr):
        print("find function at 0x%x" % addr)
        return lldb.target.ResolveLoadAddress(addr).symbol.name

    def find_global_variable(self, name):
        var = lldb.target.FindFirstGlobalVariable(name)
        if var and var.value:
            return int(var.value, 16)
        raise Exception("Cannot find the global variable: %s" % name)

    @run_async
    def step(self, timeout=10):
        # make sure we do not block the process

        # thread = process.GetThreadAtIndex(0)
        # thread = process.GetSelectedThread()
        thread = self.get_current_thread()
        cur_thread_id = thread.GetThreadID()
        print("Current thread id is %d" % cur_thread_id)

        thread.StepInstruction(False)
        time.sleep(1)

        while True:
            elapsed = 0
            print("ready to check!")
            while elapsed <= timeout:
                process = lldb.target.GetProcess()
                if process.GetState() == lldb.eStateStopped:
                    break

                print("not ready", elapsed)
                time.sleep(1)
                elapsed += 1

            if elapsed > timeout:
                raise Exception("timeout when stepping")

            if self.get_current_thread().GetThreadID() == cur_thread_id:
                # Make sure we stay at the same thread
                break
            else:
                print("different thread!!")
                lldb.target.GetProcess().Continue()
                time.sleep(2)

    @run_async
    def continue_run(self):
        print("continue to run")
        run_cmd("c")

    def isStop(self):
        # TODO: Check if it was hit at desired breakpoint
        # Make sure the process is stopped
        # target = debugger.GetSelectedTarget()
        process = lldb.target.GetProcess()
        if not process.IsValid():
            print("process is invalid")
            return False

        if process.GetState() != lldb.eStateStopped:
            print("process is not stopped %d" % process.GetState())
            return False

        return True
        # Make sure it was hit by PoC
        # output = run_cmd("showtask -F %s" % "poc")
        # for line in output.split("\n")[1:]:
        #     cols = line.split()
        #     # task = int(cols[0], 16)
        #     res = run_cmd("showcurrentthreads -s %s" % cols[0])
        #     if len(res) != 0:  # Other process hit this
        #         return True

        # print("The running process is not PoC")
        # return False

    def get_threadID(self):
        return self.get_current_thread().GetThreadID()

    def remove_breakpoints(self):
        lldb.target.DeleteAllBreakpoints()
        return True

    def set_breakpoint(self, kext, target):
        output = run_cmd("showallkexts")
        for line in output.split("\n")[1:]:
            cols = line.split()
            if len(cols) != 10:
                continue
            addr, size, name = int(cols[2], 16), int(cols[7], 16), cols[9]
            if name == kext or name.endswith(kext):
                print("Find %s at 0x%x" % (name, addr))
                cmd = "br set -a 0x%x" % (addr + target)
                print(cmd)
                run_cmd(cmd)
                break


class LLDBCommand(object):
    @classmethod
    def register_lldb_command(cls, debugger, module_name):
        # parser = cls.create_options()
        command = 'command script add -c %s.%s %s' % (module_name, cls.__name__, cls.program)
        debugger.HandleCommand(command)
        print('The "{0}" command has been installed, type "help {0}" or "{0} '
              '--help" for detailed help.'.format(cls.program))
    

def catch_exception(f):
    def wrapper(*args, **kwargs):
        ret = {}
        try:
            data = f(*args, **kwargs)
            if data:
                ret.update(data)
            ret["errcode"] = 0
        except Exception as e:
            print(e)
            ret["errcode"] = 1
        return ret

    return wrapper

class Fuzz(LLDBCommand):
    program = 'fuzz'
    def __init__(self, debugger, session_dict):
        self.parser = self.create_options()
        self.kexts = []
        print("Successfully register command fuzz")

    @classmethod
    def create_options(cls):
        parser = argparse.ArgumentParser(prog=cls.program)
        parser.add_argument("-b", "--breakpoint", action="store_true", default=False)
        parser.add_argument("-a", "--addr", type=int, help="address to set breakpoint")
        parser.add_argument("-d", "--driver", help="driver name")
        parser.add_argument("--func", help="get function address")
        parser.add_argument('--kext', help="find kext at certain address")
        return parser

    def set_breakpoint(self, kext, target):
        output = run_cmd("showallkexts")
        for line in output.split("\n")[1:]:
            cols = line.split()
            if len(cols) != 10:
                continue
            addr, size, name = int(cols[2], 16), int(cols[7], 16), cols[9]
            if name == kext or name.endswith(kext):
                print("Find %s at 0x%x" % (name, addr))
                print("br set -a 0x%x" % (addr + target))
                break

    def getFuncAddr(self, name):
        for each in lldb.target.FindFunctions(name):
            if not each.block.IsInlined():
                addr = each.symbol.addr.load_addr
                print(each.symbol.name, hex(addr))
            else:
                for start, end in each.block.ranges:
                    print("[inlined]", hex(start.load_addr), hex(end.load_addr))

    def findKext(self, addr):
        if addr.startswith("0x"):
            addr = int(addr, 16)
        else:
            addr = int(addr)

        if len(self.kexts) == 0:
            output = run_cmd("showallkexts")
            for line in output.split("\n")[1:]:
                cols = line.split()
                if len(cols) != 10:
                    continue
                start, size, name = int(cols[2], 16), int(cols[7], 16), cols[9]
                self.kexts.append((start, size, name))

        for start, size, name in self.kexts:
            if start <= addr < start + size:
                print("%s at 0x%x of size 0x%x" % (name, start, size))
                print("offset: 0x%x" % (addr - start))
                break

    def __call__(self, debugger, command, exe_ctx, result):
        command_args = shlex.split(command)
        args = self.parser.parse_args(command_args)
        if args.breakpoint:
            self.set_breakpoint("com.apple.iokit.IOBluetoothFamily", 0x10bca)
        if args.addr and args.driver:
            self.set_breakpoint(args.driver, args.addr)
        if args.func:
            self.getFuncAddr(args.func)
        elif args.kext:
            self.findKext(args.kext)


class Proxy(LLDBCommand):
    program = 'proxy'
    def __init__(self, debugger, session_dict):
        # self._debugger = debugger

        self.parser = self.create_options()
        self.debugger = LLDBDebugger()
        self.sock = None

        self.target = None
        self.task = None
        self.threadID = 0

        # target = debugger.GetSelectedTarget()
        # if target.GetNumBreakpoints() != 1:
        #     print("Failed to register proxy with %d breakpoint" % target.GetNumBreakpoints())
        # else:
        #     bp = target.GetBreakpointAtIndex(0)
        #     bp.SetScriptCallbackFunction('debug.breakpoint_externalMethod')
        print("Successfully register command proxy")

    
    @classmethod
    def create_options(cls):
        parser = argparse.ArgumentParser(prog=cls.program)
        parser.add_argument("-c", "--connect", action="store_true", default=False)
        parser.add_argument("-e", "--exit", action="store_true", default=False)
        parser.add_argument("-r", "--restart", action="store_true", default=False)
        parser.add_argument("-t", "--test", action="store_true", default=False)
        parser.add_argument("-f", "--find", action="store_true", default=False)
        return parser
    
    def __call__(self, debugger, command, exe_ctx, result):
        command_args = shlex.split(command)
        args = self.parser.parse_args(command_args)
        if args.connect:
            self.connect()
        elif args.restart:
            self.serve_forever()
        elif args.exit:
            self.disconnect()
        elif args.test:
            self.test()
        elif args.find:
            self.set_breakpoint()
        
    def test(self):
        self.debugger.isStop()

    def set_breakpoint(self):
        for each in self.debugger.read_kext_mapping():
            addr, size, name = each
            if name == "com.apple.iokit.IOBluetoothFamily":
                print(hex(addr), hex(size), name)
                print("br set -a 0x%x" % (addr + 0x10bca))

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(('localhost', 12345))
        print("successfully connect to the server")
        self.serve_forever()
        
    def disconnect(self):
        if self.sock:
            print("disconnect...")
            self.sock.close()
            self.sock = None
            
    def recvn(self, nbytes):
        remain = nbytes
        ret = b''
        while remain > 0:
            data = self.sock.recv(remain)
            if not data:
                raise Exception("connection is broken")
            ret += data
            remain -= len(data)
        return ret
    
    def send(self, data):
        if data is None:
            self.sock.sendall(struct.pack("<I", 0))
        else:
            if isinstance(data, dict):
                data = json.dumps(data).encode()
            self.sock.sendall(struct.pack("<I", len(data)))
            self.sock.sendall(data)
        
    def serve_forever(self):
        if self.sock is None: return
        print("start listening")
        while True:
            size = self.recvn(4)
            size = struct.unpack("<I", size)[0]
            data = self.recvn(size)
            request = json.loads(data)
            if self.handle_command(request):
                break
    
    @catch_exception
    def read_register(self, request):
        ret = {}
        reg_name = str(request["reg"])  # FIXME: pthon2 style
        val = self.debugger.read_register(reg_name)
        ret["val"] = val
        return ret
        
    @catch_exception
    def read_memory(self, request):
        addr = request["addr"]
        size = request["size"]
        ret = {}
        if "task" in request:
            val = self.debugger.read_user_memory(request["task"], addr, size)
        elif addr < 0xffffff0000000000 and self.task is not None:  # it could be user space address
            val = self.debugger.read_user_memory(self.task, addr, size)
        else:
            val = self.debugger.read_memory(addr, size)
        ret["val"] = val
        return ret
            
    def find_functions(self, request):
        names = request["names"]
        funcs = dict()
        for name in names:
            try:
                name = str(name)  # FIXME: pthon2 style
                ret = self.debugger.find_function_addr(name)
                funcs[name] = ret
            except Exception as e:
                print(e)
                funcs[name] = []
        return {"errcode": 0, "funcs": funcs}
    
    @catch_exception
    def find_function_name(self, request):
        name = self.debugger.find_function_name(request["addr"])
        if name is None: name = ""
        return {"name": name}

    @catch_exception
    def find_global_variable(self, request):
        name = str(request["name"])
        addr = self.debugger.find_global_variable(name)
        return {"addr": addr}

    @catch_exception
    def showallkexts(self, request):
        ret = {}
        mapping = self.debugger.read_kext_mapping()
        ret["kexts"] = mapping
        return ret
    
    @catch_exception
    def showtask(self, request):
        ret = {}
        name = str(request["name"])  # FIXME: pthon2 style
        task = self.debugger.read_task(name)
        ret["task"] = task
        return ret
    
    @catch_exception
    def setTarget(self, request):
        self.target = str(request["target"])  # FIXME: pthon2 style
        self.task = self.debugger.read_task(self.target)
        self.threadID = self.debugger.get_threadID()
        print("set target %s with 0x%x task and thread %d" % \
            (self.target, self.task, self.threadID))
        if self.task == 0:
            raise Exception("failed to get the task")
        return None

    @catch_exception
    def waitUntilBreakpoint(self, request):
        # while True:
        elapsed = 0
        while elapsed <= 15:
            if self.debugger.isStop():
                break
            time.sleep(1)
            elapsed += 1

        if elapsed > 15:
            raise Exception("timeout while waiting for breakpoint")

        # Note: our current strategy is to check whether the input is exactly the same
        # as our of testcase and thus we do not need to track the thread anymore, which
        # may have false positive.
            # if self.debugger.get_threadID() == self.threadID:
            #     break
            # print("different thread!!!!")
            # self.debugger.continue_run()
            # time.sleep(2)

    @catch_exception
    def continue_run(self, request):
        self.threadID = self.debugger.get_threadID()
        print("continue to run from %d" % self.threadID)
        self.debugger.continue_run()

    @catch_exception
    def step(self, request):
        self.debugger.step()

    @catch_exception
    def clear(self, request):
        """Ensure the VM is not stuck.
        """
        elapsed = 0
        while elapsed < 3*20:
            if self.debugger.isStop():
                self.debugger.continue_run()
            else:
                # Double check
                time.sleep(2)
                if self.debugger.isStop():
                    continue
                return

            time.sleep(3)
            elapsed += 3
        raise Exception("timeout for clearing")

    @catch_exception
    def remove_breakpoints(self, request):
        """Remove all breakpoints
        """
        self.debugger.remove_breakpoints()

    @catch_exception
    def set_breakpoint(self, request):
        self.debugger.set_breakpoint(request["kext"], request["addr"])

    def handle_command(self, request):
        cmd = request["cmd"]
        if cmd == "read reg":
            self.send(self.read_register(request))
        elif cmd == "read mem":
            reply = self.read_memory(request)
            if "val" in reply and len(reply["val"]) > 0:
                self.send(reply["val"])
            else:
                self.send(None)
        elif cmd == "pause":
            self.send({"errcode": 0})
            return True
        elif cmd == "exit":
            self.disconnect()
            return True
        elif cmd == "find func":
            self.send(self.find_functions(request))
        elif cmd == "find name":
            self.send(self.find_function_name(request))
        elif cmd == "find var":
            self.send(self.find_global_variable(request))
        elif cmd == "showallkexts":
            self.send(self.showallkexts(request))
        elif cmd == "showtask":
            self.send(self.showtask(request))
        elif cmd == "set target":
            self.send(self.setTarget(request))
        elif cmd == "wait":
            self.send(self.waitUntilBreakpoint(request))
        elif cmd == "continue":
            self.send(self.continue_run(request))
        elif cmd == "step":
            self.send(self.step(request))
        elif cmd == "clear":
            self.send(self.clear(request))
        elif cmd == "rm bp":
            self.send(self.remove_breakpoints(request))
        elif cmd == "set bp":
            self.send(self.set_breakpoint(request))
        else:
            print("unsupported command %s" % cmd)
            self.send({"errcode": 2})
        return False

def __lldb_init_module(debugger, dict):
    # Register all classes that have a register_lldb_command method
    # for _name, cls in inspect.getmembers(sys.modules[__name__]):
    #     if inspect.isclass(cls) and callable(getattr(cls,
    #                                                  "register_lldb_command",
    #                                                  None)):
    #         cls.register_lldb_command(debugger, __name__)
    Proxy.register_lldb_command(debugger, __name__)
    Fuzz.register_lldb_command(debugger, __name__)

