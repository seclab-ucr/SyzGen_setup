
import logging
import angr

from collections import deque
from angr.errors import SimConcreteRegisterError
from angr.sim_manager import SimulationManager

from ..debugger.proxy import DebuggerConcreteTarget, ProxyException
from ..models.procedures import runAction, MemPrepare, MemWriteBytes, DummyStub, IOMalloc, \
    KallocCanblock, bzero, Snprintf, MemReadBytes, MemmoveChk, Memmove, Strnlen, \
    Memset, MemWithAddressRange, KernelThreadStart, OSAddAtomic16, OSSymbolString, InitWithPhysicalMask, \
    IOBufferSetLength, IOBufferGetBytesNoCopy, ClockGetTime, ThreadWakeupThread, MakeMapping, GetVirtualAddress, \
    dummyStubFunc, IORecursiveLockLock, GetMemoryDescriptor, IOWorkLoopRunAction, copyClientEntitlement, \
    IOBufferAppendBytes, MemWithAddress, ReadRandom, Copyin, OSStringWithCString, Zalloc, MacModel
from ..kext.helper import DbgHelper
from ..kext.macho import parse_vtables
from ..utils import getConfigKey

logger = logging.getLogger(__name__)

class BaseExecutor:
    def __init__(self, binary, model=None):
        self.filename = binary
        self.model = model

        self.should_abort = False
        self.proj = angr.Project(self.filename)

        self.setup_hooks()

    def abort(self):
        self.should_abort = True

    def getInitState(self):
        raise NotImplementedError

    def pre_execute(self, state):
        raise NotImplementedError

    def post_execute(self, simgr):
        """Show error stack backtrace for debugging purpose
        """
        if len(simgr.errored) > 0:
            for each in simgr.errored:
                self.show_backtrace(each.state)
                print("\n\n")

            # For debugging purpose
            from IPython import embed; embed()
            raise Exception("Error state!")
        return True

    def execute(self, simgr: SimulationManager) -> SimulationManager:
        raise NotImplementedError

    def show_backtrace(self, state):
        print("Show error state stack frames: 0x%x" % state.addr)
        for i, f in enumerate(state.callstack):
            print("Frame %d: %#x => %#x" % (i, f.call_site_addr, f.func_addr))

    def run(self):
        simgr = None
        try:
            state = self.getInitState()

            self.pre_execute(state)
            simgr = self.proj.factory.simgr(state)
            simgr = self.execute(simgr)
            return self.post_execute(simgr)
        except Exception as e:
            raise e

    def getFuncAddrs(self, *funcs):
        '''
        param funcs: function names
        return a list of tuple <func name, addr>
        '''
        ret = list()
        for func in funcs:
            sym = self.proj.loader.find_symbol(func)
            if sym is None:
                raise Exception("Unknown symbol %s" % func)
            ret.append((func, sym.rebased_addr))
        return ret

    def getFuncAddr(self, name):
        return self.getFuncAddrs(name)[0][1]

    def setup_hooks(self):
        if self.model is None:
            return

        models = self.model.getFunc2Model()
        names = list(models)
        for func, addr in self.getFuncAddrs(*names):
            logger.debug("Replace %s at 0x%x" % (func, addr))
            self.proj.hook(addr, models[func])

        hooks = self.model.getFunc2Hook()
        names = list(hooks)
        for func, addr in self.getFuncAddrs(*names):
            logger.debug("Hook %s at 0x%x" % (func, addr))
            self.proj.hook(addr, hooks[func], length=0)

#
# under-context symbolic execution
#

class Executor(BaseExecutor):
    """
    Under-context static analysis: perform static analysis after dynamic execution in order to 
    resolve most function pointers.
    Note: Similar to symbolic execution, but we optimize it to cater our purpose.
    """
    def __init__(self, proxy, binary, target, entry=0, isConcolic=False, model=None):
        self.proxy = proxy    # Set proxy first before we call super init
        self.isConcolic = isConcolic

        # initial project
        self.entry = entry

        super(Executor, self).__init__(binary, model=model)
        
    def getInitState(self):
        target = DebuggerConcreteTarget(self.proxy)
        state = self.proj.factory.blank_state()
        state.memory.mem._memory_backer.set_concrete_target(target)

        # synchronize registers
        for reg in state.arch.register_list:
            if (reg.concrete and reg.general_purpose) or reg.name == "gs":
                try:
                    reg_val = target.read_register(reg.name)
                    setattr(state.regs, reg.name, reg_val)
                    print("sync %s: 0x%x" % (reg.name, reg_val))
                except SimConcreteRegisterError as e:
                    print("Failed to read register:", e)
                    raise ProxyException("Failed to sync register")

        return state

    
class LinuxExecutor(Executor):
    def __init__(self, proxy, binary, target="kernel", entry=0, isConcolic=False):
        super(LinuxExecutor, self).__init__(proxy, binary, target, entry, isConcolic)


class MacExecutor(Executor):
    def __init__(self, proxy, binary, target, entry=0, isConcolic=False):
        self.kexts = []
        self.target = target
        self.target_base = 0
        self.load_module(proxy)    # load all kext modules, it has to be called first

        super(MacExecutor, self).__init__(proxy, binary, target, entry, isConcolic, model=MacModel())

        self.first_inst = None
        if entry:
            block = self.proj.factory.block(entry)
            self.first_inst = block.capstone.insns[0]

        self.hook_functions()    # load function summaries

    def load_module(self, proxy):
        self.kexts = proxy.read_kext_mapping()
        for (addr, size, name) in self.kexts:
            if name == self.target:
                print(hex(addr), hex(size), name)
                self.target_base = addr

    def getBaseAddr(self, ip, target=None):
        for (addr, size, name) in self.kexts:
            if addr <= ip < addr + size:
                if target and name != target:
                    return "", 0
                return name, ip - addr
        return "", 0

    def getTargetAddr(self, offset, target):
        for (addr, size, name) in self.kexts:
            if name == target:
                if offset < size:
                    return addr+offset
        return 0

    def getFuncAddrs(self, *funcs):
        ret = []
        res = self.proxy.find_functions_addr(list(funcs))
        for name, ents in res.items():
            for ent in ents:
                if not ent["inlined"]:
                    ret.append((name, ent["addr"]))
                    break
        return ret

    def hook_functions(self):
        funcWithZero = DummyStub()
        funcWithOne = DummyStub(ret_value=1)
               
        # We allow user to define some function hooks
        for driver, addrs in getConfigKey("funcWithZero", default={}).items():
            for addr in addrs:
                real_addr = self.getTargetAddr(addr, driver)
                print("hook with funcWithZero:", driver, hex(addr), hex(real_addr))
                if real_addr:
                    self.proj.hook(real_addr, funcWithZero)
        for driver, addrs in getConfigKey("funcWithOne", default={}).items():
            for addr in addrs:
                real_addr = self.getTargetAddr(addr, driver)
                print("hook with funcWithOne:", driver, hex(addr), hex(real_addr))
                if real_addr:
                    self.proj.hook(real_addr, funcWithOne)

        # for ent in funcs["IORecursiveLockUnlock"]:
        #     if ent["inlined"]:
        #         block = self.proj.factory.block(ent["start"])
        #         print("Replace inlined function %s from 0x%x-0x%x" % (name, ent["start"], ent["end"]))
                # self.proj.hook(ent["start"], inlined_summaries[name], length=ent["end"]-ent["start"])

        # for i in range(len(names)):
        #     print("Replace %s at 0x%x" % (names[i], addrs[i]))
        #     self.proj.hook(addrs[i], summaries[names[i]])

        funcs = self.proxy.find_functions_addr(["IOMemoryDescriptor::withAddressRange"])
        for ent in funcs["IOMemoryDescriptor::withAddressRange"]:
            if not ent["inlined"]:
                print("Replace IOMemoryDescriptor::withAddressRange at 0x%x" % ent["addr"])
                self.proj.hook(ent["addr"], MemWithAddressRange(orig_func=ent["addr"]))

        funcs = self.proxy.find_functions_addr(["IOMemoryDescriptor::withAddress"])
        for ent in funcs["IOMemoryDescriptor::withAddress"]:
            if not ent["inlined"]:
                print("Replace IOMemoryDescriptor::withAddress at 0x%x" % ent["addr"])
                self.proj.hook(ent["addr"], MemWithAddress(orig_func=ent["addr"]))

    def getInitState(self):
        state = super(MacExecutor, self).getInitState()
        
        # Get some global variables necessary for procedure modeling.
        pkIOBooleanTrue = self.proxy.find_global_variable("kOSBooleanTrue")
        kIOBooleanTrue = state.solver.eval(state.mem[pkIOBooleanTrue].uint64_t.resolved)
        state.globals["kIOBooleanTrue"] = kIOBooleanTrue

        # set self
        state.globals["executor"] = self

        self.setDeadEnd(state)

        # Fix first instruction that is set to int3
        # Note it must be set before we execute any instruction, otherwise the old one will be cachced.
        # int3 only has one bytes and thus any instruction would be sufficient to overwrite it.
        if self.entry:
            state.memory.store(self.entry+self.target_base, state.solver.BVV(self.first_inst.bytes), inspect=False)
        
        return state

    def setDeadEnd(self, state):
        # set return address
        ret_addr = self.proj.simos.return_deadend
        # Assume we just run into this function and stack pointer is not tampered.
        # terminate when this function is finished.
        print("reg rsp:", state.regs.rsp)
        print(state.mem[state.regs.rsp].uint64_t.resolved)
        state.memory.store(state.regs.rsp, state.solver.BVV(ret_addr, 64), endness=state.arch.memory_endness, inspect=False)

    def show_backtrace(self, state):
        print("Show error state stack frames: 0x%x" % state.addr)
        for i, f in enumerate(state.callstack):
            print("Frame %d: %#x => %#x" % (i, f.call_site_addr, f.func_addr))
            callName, funcName = "", ""
            if f.call_site_addr > 0xffffff8000000000:
                callName = self.proxy.find_function_name(f.call_site_addr)
            else:
                driver, addr = self.getBaseAddr(f.call_site_addr)
                callName = "%s(+0x%x)" % (driver, addr)
            if f.func_addr > 0xffffff8000000000:
                funcName = self.proxy.find_function_name(f.func_addr)
            else:
                driver, addr = self.getBaseAddr(f.func_addr)
                funcName = "%s(+0x%x)" % (driver, addr)
            print("%s => %s" % (callName, funcName))


#
# static symbolic execution
#
class StaticExecutor(BaseExecutor):
    """Perform symbolic execution on a single function
    """

    def __init__(self, binary, func, start, end=None):
        super(StaticExecutor, self).__init__(binary)
        self._func = func
        self._start = start
        self._end = end if end else self._start + self.getFuncSize(func)
        self.queue = deque()
        print(hex(self._start), hex(self._end))

        # Get vtables for all class
        self.metaClazz = parse_vtables(self.proj)

    def getInitState(self):
        # FIX relocation symbols
        state = self.proj.factory.blank_state(addr=self._start)
        return state


    def run(self):
        print("run")
        state = self.getInitState()
        self.pre_execute(state)

        self.queue.append(state)
        while self.queue and not self.should_abort:
            cur = self.queue.popleft()
            for work in self.execute(cur):
                logger.debug("add one work 0x%x" % work.addr)
                self.queue.append(work)

        return self.post_execute()

    def handle_state(self, state, block):
        raise Exception("handle_state is not implemented")

    def execute(self, state):
        ret = []
        if not self._start <= state.addr < self._end:
            return ret

        node = self.proj.factory.block(state.addr)
        if node is None:
            return ret

        num_inst = None if node is None else len(node.instruction_addrs)
        logger.debug("Executing 0x%x: %d" % (state.addr, len(node.instruction_addrs)))
        sim_successors = self.proj.factory.successors(state, num_inst=num_inst)
        isCall = False if node is None else node.capstone.insns[-1].mnemonic == 'call'
        nxt_addr = node.addr + node.size

        todo = []
        for succ in sim_successors.flat_successors:
            if self.handle_state(succ, node):
                # stop
                continue

            # Because we did not fix relocatable call target, some call instructions calling
            # external functions may seem to jump to next instruction.
            if isCall or not self._start <= succ.addr < self._end:
                # jmp can also call other functions but it doesn't return
                succ.regs.ip = nxt_addr if isCall else 0
                succ.regs.rax = state.solver.BVS("ret_value", 64)

            todo.append(succ)

        if isCall and len(todo) > 128:
            todo = sim_successors[:128]

        for succ in sim_successors.unconstrained_successors:
            # deference unknown function ptr results in too many successors
            if isCall:
                succ.regs.ip = nxt_addr  # skip this instruction
                succ.regs.rax = state.solver.BVS("ret_value", 64)
            else:
                succ.regs.ip = 0  # no need to continue

        return todo + sim_successors.unconstrained_successors

    def pre_execute(self, state):
        pass

    def post_execute(self):
        pass

    #
    # Utility
    #
    def getFuncSize(self, func):
        lldb = DbgHelper(self.filename)
        return lldb.getFuncSize(self.proj, func.name, func.relative_addr)
