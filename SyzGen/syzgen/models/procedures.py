
import logging
from pathlib import Path
from syzgen.debugger.lldbproxy import LLDBDebugger
import angr
import time
import random

from ..utils import extractField, extractFields, extractSymbol, getConfigKey
from claripy.ast.bv import Extract, Reverse

from . import BaseModel, DummyModel, MAX_MEMORY_SIZE, brkAlloc, Memset

logger = logging.getLogger(__name__)

#
# General Function Summaries
#

class IOMalloc(angr.SimProcedure):
    def run(self, length):
        print("call IOMalloc", length)
        return brkAlloc(self.state, length)

class Zalloc(angr.SimProcedure):
    def run(self, zone):
        # FIXME: how to get the offset: p &(((zone_t)0)->elem_size)
        elem_size = self.state.mem[zone+0xc8].uint64_t.resolved
        print("call zalloc", zone, elem_size)
        return brkAlloc(self.state, elem_size)

class KallocCanblock(angr.SimProcedure):
    def run(self, psize, canBlock, site):
        length = self.state.mem[psize].uint64_t.resolved
        print("call kalloc_canblock", psize, canBlock, site, length)
        return brkAlloc(self.state, length)

class runAction(angr.SimProcedure):
    """IOCommandGate::runAction
    """
    IS_FUNCTION = True
    
    def run(self, this, action, arg0, arg1, arg2, arg3):
        print("call IOCommandGate::runAction")
        # There is definitely no refs
        # FIXME: do not hardcode the offset (IOCommandGate->owner)
        owner = self.state.mem[this+0x18].uint64_t.resolved 
        self.call(action, [owner, arg0, arg1, arg2, arg3], "retFromRunAction")
        
    def retFromRunAction(self, this, action, arg0, arg1, arg2, arg3):
        print("return from action")
        self.ret(0)

class IOWorkLoopRunAction(angr.SimProcedure):
    """IOReturn IOWorkLoop::runAction(Action inAction, OSObject *target,
        void *arg0, void *arg1, void *arg2, void *arg3)
    """
    IS_FUNCTION = True

    def run(self, this, action, target, arg0, arg1, arg2, arg3):
        print("call IOWorkLoop::runAction", action, target, arg0, arg1, arg2, arg3)
        return self.call(action, [target, arg0, arg1, arg2, arg3], "retFromRunAction")

    def retFromRunAction(self, this, action, target, arg0, arg1, arg2, arg3):
        return 0

class MemPrepare(angr.SimProcedure):
    def run(self, this, direction):
        print("call prepare")
        return 0

class MemWriteBytes(angr.SimProcedure):
    def run(self, this, offset, dst, length):
        print("on WriteBytes", this, offset, dst, length)
        return length

class MemReadBytes(angr.SimProcedure):
    def run(self, this, offset, dst, length):
        print("on ReadBytes", this, offset, dst, length)
        # p &(((IOMemoryDescriptor*)0)->_length)
        addr = self.state.solver.eval(this)
        if self.state.solver.symbolic(length):
            size = self.state.solver.max_int(length)
            if size > 1024: size = 1024
        else:
            size = self.state.solver.eval(length)

        ptr, sym_cont = self.state.locals.get(('mapping', addr), (None, None))
        if sym_cont is None:
            if ptr is None:
                raise Exception("failed to find the mapping 0x%x" % addr)
            # We have assigned a concrete pointer to it but its content may not be symbolic (they did not come
            # from user space) and thus we need to retrieve this.
            sym_cont = self.state.memory.load(ptr, size, inspect=False)
        
        concrete_offset = self.state.solver.eval(offset)
        print(sym_cont, sym_cont.length, concrete_offset, size)
        if concrete_offset*8 >= sym_cont.length:
            raise Exception("offset exceeds")
        left, right, remain = concrete_offset, concrete_offset+size, 0
        if right*8 > sym_cont.length:
            remain = right-(sym_cont.length//8)
            right = sym_cont.length//8

        if left == 0 and right*8 == sym_cont.length:
            self.state.memory.store(dst, sym_cont)
        else:
            self.state.memory.store(dst, Extract(sym_cont.length-left*8-1, sym_cont.length-right*8, sym_cont))

        if remain > 0: # Padding with zero
            self.state.memory.store(dst+(sym_cont.length//8), self.state.solver.BVV(0, remain*8))

        # TODO: concrete or symbolic?
        return size

class MakeMapping(angr.SimProcedure):
    """IOMemoryMap *IOMemoryDescriptor::makeMapping(
        IOMemoryDescriptor *    owner,
        task_t                  __intoTask,
        IOVirtualAddress        __address,
        IOOptionBits            options,
        IOByteCount             __offset,
        IOByteCount             __length )
    """
    def run(self, this, owner, task, mapping, options, offset, length):
        print("call IOMemoryDescriptor::makeMapping", this, mapping)
        pmapping = self.state.solver.eval(mapping)
        addr = self.state.solver.eval(this)
        self.state.locals[('mapping', pmapping)] = addr

        # length = self.state.memory.load(pmapping+0x30, 8, endness=self.state.arch.memory_endness, inspect=False)
        # print("map length: ", length, self.state.solver.eval(length))
        # length = self.state.memory.load(addr+0x50, 8, endness=self.state.arch.memory_endness, inspect=False)
        # print("IOMemoryDescriptor length: ", length, self.state.solver.eval(length))
        return pmapping

class GetVirtualAddress(angr.SimProcedure):
    """virtual IOVirtualAddress IOMemoryMap::getVirtualAddress(void);
    """
    def run(self, this):
        addr = self.state.solver.eval(this)
        owner = self.state.locals.get(('mapping', addr), 0)
        print("call IOMemoryMap::getVirtualAddress 0x%x" % addr)
        if owner == 0:
            raise Exception("failed to find IOMemoryDescriptor from IOMemoryMap")
        ptr, _ = self.state.locals.get(('mapping', owner), (None, None))
        if ptr is None:
            raise Exception("failed to find the mapping 0x%x" % owner)
        return ptr

class GetMemoryDescriptor(angr.SimProcedure):
    """IOMemoryDescriptor * IOMemoryMap::getMemoryDescriptor()
    """
    def run(self, this):
        print("call getMemoryDescriptor", this)
        pmapping = self.state.solver.eval(this)
        key = ('mapping', pmapping)
        return self.state.locals[key]

def trackLength(state, addr, length):
    # Mapping from len to ptr
    len_sym, len_l, len_r = extractSymbol(length)
    addr_sym, addr_l, addr_r = extractSymbol(addr)
    if len_sym is not None and addr_sym is not None:
        var = Reverse(Extract(len_l, len_r, len_sym))
        concrete_vars = state.solver.eval_upto(var, 1, extra_constraints=[var != 0])
        if concrete_vars:
            concrete_var = concrete_vars[0]
            concrete_lens = state.solver.eval_upto(length, 1, extra_constraints=[var == concrete_var])
            if concrete_lens:
                concrete_len = concrete_lens[0]

            if concrete_len%concrete_var != 0:
                logger.warning("length is not a muliplier of the input: %d %d" % (concrete_len, concrete_var))

            print("trackLength", concrete_var, concrete_len)
            lens = state.locals.get("lens", {})
            lens[(len_sym._encoded_name, len_l, len_r)] = (addr_sym._encoded_name, addr_l, addr_r, concrete_len//concrete_var)
            state.locals["lens"] = lens

def CopyFromUser(state, addr, length):
    # if not state.solver.symbolic(addr):
    #     raise Exception("Potentially read non-symbolic content from user space")

    if state.solver.symbolic(length):
        trackLength(state, addr, length)

    # concretize addr and length
    rep = addr.ast.__repr__(inner=True)
    ptr = None

    size = state.solver.max_int(length)
    # FIXME: 1024??
    # Add a hard constraint here.
    if size > MAX_MEMORY_SIZE: 
        size = MAX_MEMORY_SIZE
        state.solver.add(length <= MAX_MEMORY_SIZE)

    solutions = state.solver.eval_upto(addr, 2)
    if len(solutions) > 1:
        # if we didn't concretize this to a pointer, assign one here.
        # find the corresponding pointer address if exists. Otherwise, malloc a new one
        for k, v in state.solver.get_variables('ptr'):
            p = state.solver.eval(v)
            if k[1] == rep:
                ptr = p
                break

        if ptr is None:
            ptr = brkAlloc(state, size)

        # make sure the pointer has a concrete solution
        ptr_bv = state.solver.BVV(ptr, 64)
        print("add constraints", addr, ptr_bv)
        state.solver.add(addr == ptr_bv)
        # register this pointer to make sure the assignment is consistent across all states
        state.solver.register_variable(ptr_bv, ('ptr', rep), eternal=True)
    else:
        ptr = solutions[0]
        # We have concretized this pointer before, thus the corresponding memory region is already
        # created. Fix the size to stick to previous value.
        for _, sym in state.solver.get_variables('mem', ptr):
            size = sym.length//8

    return ptr, size

def mapping(state, addr, length, descriptor):
    """Connect IOMemoryDescriptor to this address"""
    solutions = state.solver.eval_upto(addr, 2)
    if len(solutions) > 1:
        print(addr, solutions)
        raise Exception("addr has multiple solutions")
    ptr = solutions[0]
    # FIXME: We assume no overlapping.
    # TODO: Correctly get the corresponding symbol given any pointer
    variables = list(state.solver.get_variables('mem', ptr))
    print("Check mem variables", ptr, variables)
    sym_cont = None
    if len(variables) == 0:
        # we have not set the symbolic variable for those self-assigned pointers
        size = state.solver.max_int(length)
        if size > 1024: size = 1024
        if ptr < 0xffffff8000000000:
            sym_cont = state.solver.BVS("mem_%x" % ptr, size*8, key=("mem", ptr), eternal=True)
            # check dependence when we create new symbolic variable
            # find_dependence(self.state, addr, ptr)
            # Also copy it to the self-assigned address
            state.memory.store(ptr, sym_cont, inspect=False)
        # If it is a kernel pointer we can directly read content.
        # Leave sym_cont to None, and then it can directly load its content from that address.
    elif len(variables) == 1:
        _, sym_cont = variables[0]
    else:
        print(variables)
        raise Exception("multiple variables for mem_%x" % ptr)
    
    # store the mapping info
    state.locals[('mapping', descriptor)] = (ptr, sym_cont)

class MemWithAddress(angr.SimProcedure):
    """IOMemoryDescriptor *
    IOMemoryDescriptor::withAddress(void *      address,
                                    IOByteCount   length,
                                    IODirection direction)
    WithAddressRange is inlined in this function.
    """
    def run(self, addr, length, direction, orig_func=None):
        print("WithAddress", addr, length, direction)
        ptr, size = CopyFromUser(self.state, addr, length)

        self.call(orig_func, (ptr, size, direction), "getReturn", jumpkind="Ijk_NoHook")

    def getReturn(self, addr, length, direction, orig_func=None):
        ret = self.state.regs.rax
        print("return from WithAddress", addr, length, direction, ret)
        ret_addr = self.state.solver.eval(ret)
        if ret_addr != 0:
            mapping(self.state, addr, length, ret_addr)
            self.state.memory.store(ret_addr+0x50, length, endness=self.state.arch.memory_endness, inspect=False)  # _length
        return ret

class MemWithAddressRange(angr.SimProcedure):
    def run(self, addr, length, options, task, orig_func=None):
        print("WithAddressRange", addr, length, options, task, orig_func)
        ptr, size = CopyFromUser(self.state, addr, length)
        print(hex(ptr), size)
            
        self.call(orig_func, (ptr, size, options, task), "getReturn", jumpkind="Ijk_NoHook")
        
    def getReturn(self, addr, length, options, task, orig_func=None):
        ret = self.state.regs.rax
        print("return from WithAddressRange:", addr, length, options, task, orig_func, ret)
        if not self.state.solver.symbolic(addr) and self.state.solver.eval(addr) == 0:
            # FIXME: something wrong happened.
            logger.warning("addr becomes zero!!")
            return 0

        ret_addr = self.state.solver.eval(ret)
        if ret_addr != 0:
            print("mapping", hex(ret_addr))
            mapping(self.state, addr, length, ret_addr)
            self.state.memory.store(ret_addr+0x50, length, endness=self.state.arch.memory_endness, inspect=False)  # _length
        return ret

class DummyStub(angr.SimProcedure):
    def run(self, ret_value=0):
        if ret_value is not None:
            return ret_value

def dummyStubFunc(state):
    pass

class InitWithPhysicalMask(angr.SimProcedure):
    """bool IOBufferMemoryDescriptor::initWithPhysicalMask(
        task_t            inTask,
        IOOptionBits      options,
        mach_vm_size_t    capacity,
        mach_vm_address_t alignment,
        mach_vm_address_t physicalMask)
    """
    def run(self, this, inTask, options, capacity, alignment, physicalMask):
        print("call InitWithPhysicalMask:", this, inTask, options, capacity, alignment, physicalMask)
        if self.state.solver.max(capacity) == 0:
            return 0
        self.state.memory.store(this+0xc0, capacity, endness=self.state.arch.memory_endness, inspect=False)  # _capacity
        ptr = brkAlloc(self.state, capacity)
        print("call InitWithPhysicalMask", ptr)
        _bufferOffset = LLDBDebugger.fieldOffset("_length", "IOBufferMemoryDescriptor", getConfigKey("kernel"))
        self.state.memory.store(this+_bufferOffset, ptr, endness=self.state.arch.memory_endness, inspect=False)  # _buffer
        # store the mapping info
        self.state.locals[('mapping', self.state.solver.eval(this))] = (ptr, None)
        return 1

class IOBufferSetLength(angr.SimProcedure):
    """void IOBufferMemoryDescriptor::setLength(vm_size_t length)"""
    def run(self, this, length):
        _lengthOffset = LLDBDebugger.fieldOffset("_length", "IOBufferMemoryDescriptor", getConfigKey("kernel"))
        self.state.memory.store(this+_lengthOffset, length, endness=self.state.arch.memory_endness, inspect=False)  # _length

class IOBufferGetBytesNoCopy(angr.SimProcedure):
    def run(self, this):
        """IOBufferMemoryDescriptor::getBytesNoCopy(void)"""
        print("call getBytesNoCopy", this)
        _bufferOffset = LLDBDebugger.fieldOffset("_buffer", "IOBufferMemoryDescriptor", getConfigKey("kernel"))
        return self.state.mem[this+_bufferOffset].uint64_t.resolved

# IOBufferMemoryDescriptor::withBytes(const void * inBytes,
#     vm_size_t    inLength,
#     IODirection  inDirection,
#     bool         inContiguous)
# It creates an object, call initWithPhysicalMask and then call appendBytes.
class IOBufferAppendBytes(angr.SimProcedure):
    """IOBufferMemoryDescriptor::appendBytes(const void * bytes, vm_size_t withLength)
    Note we assume it was only called by withBytes and thus _length is 0.
    TODO: check capacity and length
    """
    def run(self, this, addr, length):
        print("call IOBufferMemoryDescriptor::appendBytes", this, addr, length)
        # Assign a concrete pointer to the symbolic addr
        ptr, size = CopyFromUser(self.state, addr, length)
        if size == 0:
            return 0

        variables = list(self.state.solver.get_variables('mem', ptr))
        sym_cont = None
        if len(variables) == 0:
            if ptr < 0xffffff8000000000:
                # we have not set the symbolic variable for those self-assigned pointers
                sym_cont = self.state.solver.BVS("mem_%x" % ptr, size*8, key=("mem", ptr), eternal=True)
                self.state.memory.store(ptr, sym_cont, inspect=False)
            else:
                # If it is a kernel pointer we can directly read content.
                sym_cont = self.state.memory.load(ptr, size, inspect=False)
        elif len(variables) == 1:
            _, sym_cont = variables[0]
        else:
            print(variables)
            raise Exception("multiple variables for mem_%x" % ptr)

        _bufferOffset = LLDBDebugger.fieldOffset("_buffer", "IOBufferMemoryDescriptor", getConfigKey("kernel"))
        buf = self.state.mem[this+_bufferOffset].uint64_t.concrete  # _buffer
        self.state.memory.store(buf, sym_cont, inspect=False)  # We assume the offset is zero.
        origin_length = self.state.solver.eval(self.state.mem[this+0x50].uint64_t.resolved)
        if origin_length != 0:
            print("original length is %d" % origin_length)
            raise Exception("original is not zero: %d" % origin_length)
        # FIXME: when calling getLength, it returns this concrete length (ie., concretization)
        _lengthOffset = LLDBDebugger.fieldOffset("_length", "IOBufferMemoryDescriptor", getConfigKey("kernel"))
        self.state.memory.store(this+_lengthOffset, self.state.solver.BVV(size, 64), \
            endness=self.state.arch.memory_endness)  # _length
        # store the mapping info
        self.state.locals[('mapping', self.state.solver.eval(this))] = (buf, sym_cont)
        return 1

class Copyin(angr.SimProcedure):
    def run(self, uaddr, kaddr, length):
        print("Copyin", uaddr, kaddr, length)
        state = self.state
        ptr, size = CopyFromUser(self.state, uaddr, length)

        # FIXME: We assume no overlapping.
        # TODO: Correctly get the corresponding symbol given any pointer
        variables = list(state.solver.get_variables('mem', ptr))
        print("Check mem variables", ptr, variables)
        sym_cont = None
        if len(variables) == 0:
            # we have not set the symbolic variable for those self-assigned pointers
            size = state.solver.max_int(length)
            if size > 1024: size = 1024
            if ptr < 0xffffff8000000000:
                sym_cont = state.solver.BVS("mem_%x" % ptr, size*8, key=("mem", ptr), eternal=True)
                # Also copy it to the self-assigned address
                state.memory.store(ptr, sym_cont, inspect=False)
                state.memory.store(kaddr, sym_cont, inspect=False)
            else:
                src_mem = state.memory.load(ptr, size, inspect=False)
                state.memory.store(kaddr, src_mem, inspect=False)
        elif len(variables) == 1:
            _, sym_cont = variables[0]
            state.memory.store(kaddr, sym_cont, inspect=False)
        else:
            print(variables)
            raise Exception("multiple variables for mem_%x" % ptr)
        
        return length

class bzero(angr.SimProcedure):
    def run(self, dst, length):
        if self.state.solver.symbolic(length):
            size = self.state.solver.max_int(length)
            if size > MAX_MEMORY_SIZE: size = MAX_MEMORY_SIZE
        else:
            size = self.state.solver.eval(length)
        ptr = self.state.solver.eval(dst)
        print("bzero", ptr, size)
        for i in range(size):
            self.state.memory.store(ptr+i, self.state.solver.BVV(0, 8), inspect=False)

class Snprintf(angr.SimProcedure):
    def run(self, dst, length, fmt):
        # In the driver we tested, snprintf does not matter
        self.state.memory.store(dst, self.state.solver.BVV(0, 8), inspect=False)
        return 0

class MemmoveChk(angr.SimProcedure):
    def run(self, dst, src, srcLen, dstLen):
        # srcLen <= dstLen
        print("call __memmove_chk", dst, src, srcLen, dstLen)
        if not self.state.solver.symbolic(srcLen):
            conditional_size = self.state.solver.eval(srcLen)
        else:
            max_limit = self.state.solver.max_int(srcLen)
            min_limit = self.state.solver.min_int(srcLen)
            conditional_size = min(MAX_MEMORY_SIZE, max(min_limit, max_limit))
        if not self.state.solver.symbolic(dstLen):
            concrete = self.state.solver.eval(dstLen)
            conditional_size = min(conditional_size, concrete)

        if conditional_size > 0:
            print("__memmove_chk with size %d" % conditional_size)
            src_mem = self.state.memory.load(src, conditional_size)
            self.state.memory.store(dst, src_mem, size=conditional_size)

        return dst
        
class Memmove(angr.SimProcedure):
    def run(self, dst, src, srcLen):
        print("call memmove", dst, src, srcLen)
        if not self.state.solver.symbolic(srcLen):
            conditional_size = self.state.solver.eval(srcLen)
        else:
            max_limit = self.state.solver.max_int(srcLen)
            min_limit = self.state.solver.min_int(srcLen)
            conditional_size = min(MAX_MEMORY_SIZE, max(min_limit, max_limit))
        if conditional_size > 0:
            print("memmove with size %d" % conditional_size)
            src_mem = self.state.memory.load(src, conditional_size)
            self.state.memory.store(dst, src_mem, size=conditional_size)

        return dst

def addStringVariable(state, sym, left, right):
    if sym is not None:
        variables = state.locals.get("variables", set())
        variables.add((sym, left, right))
        state.locals["variables"] = variables

        strings = state.locals.get("strings", set())
        strings.add((sym, left, right))
        state.locals["strings"] = strings

class Strnlen(angr.SimProcedure):
    def run(self, src, limit):
        print("call strnlen", src, limit)
        if not self.state.solver.symbolic(limit):
            conditional_size = self.state.solver.eval(limit)
        else:
            max_limit = self.state.solver.max_int(limit)
            min_limit = self.state.solver.min_int(limit)
            conditional_size = min(MAX_MEMORY_SIZE, max(min_limit, max_limit))
        
        src_addr = self.state.solver.eval(src)
        max_size = conditional_size
        min_size = 0
        fields = set()
        for i in range(conditional_size):
            c = self.state.memory.load(src_addr+i, 1, inspect=False)
            extractFields(c, fields)
            if not self.state.solver.symbolic(c):
                if self.state.solver.is_true(c == 0):
                    max_size = i
                    break
                else:
                    min_size = i
        print("max_size: %d, min_size: %d" % (max_size, min_size))

        # Mark the boundary of the string
        l, r, sym = 0, 0, None
        for (name, left, right) in fields:
            if sym is None and l == 0 and r == 0:
                l, r, sym = left, right, name
            else:
                if left > l: l = left
                if right < r: r= right
                if name != sym: sym = None
        print(sym, l, r)
        addStringVariable(self.state, sym, l, r)

        ret_len = self.state.solver.BVS("strnlen_ret", 64, inspect=False, events=False)
        self.state.solver.add(ret_len <= max_size)
        self.state.solver.add(ret_len >= min_size)
        return ret_len

class KernelThreadStart(angr.SimProcedure):
    """https://developer.apple.com/documentation/kernel/1429094-kernel_thread_start
    kern_return_t kernel_thread_start(thread_continue_t continuation, void *parameter, thread_t *new_thread);
    """
    def run(self, func, param, thread):
        print("kernel_thread_start", func)
        return 0

class ThreadWakeupThread(angr.SimProcedure):
    def run(self):
        print("call thread_wakeup_thread")

class OSAddAtomic16(angr.SimProcedure):
    """https://developer.apple.com/documentation/kernel/1576475-osaddatomic16?language=objc
    """
    def run(self, amount, addr):
        print("call OSAddAtomic16", amount, addr)
        val = self.state.mem[addr].uint16_t.resolved
        new_val = val + self.state.regs.di
        self.state.memory.store(addr, new_val, endness=self.state.arch.memory_endness, inspect=False)
        return val

def annotate_string(state, ptr):
    first = state.memory.load(ptr, 1, inspect=False)
    if state.solver.symbolic(first):
        print("annotate string:", first)
        concrete_ptr = state.solver.eval(ptr)
        sym, _, _ = extractSymbol(first)
        if sym is not None:
            addStringVariable(state, sym._encoded_name, sym.length-1, 0)

def OSSymbolString(state):
    ptr = state.regs.rdi
    print("OSSymbolString", ptr)
    annotate_string(state, ptr)

def OSStringWithCString(state):
    ptr = state.regs.rdi
    print("OSString::withCString", ptr)
    annotate_string(state, ptr)

class ClockGetTime(angr.SimProcedure):
    def run(self, secp, usecp):
        t = time.time()
        sec = int(t)
        usec = int((t-sec)*1000000)
        self.state.memory.store(secp, self.state.solver.BVV(sec, 32), inspect=False)
        self.state.memory.store(usecp, self.state.solver.BVV(usec, 32), inspect=False)

def IORecursiveLockLock(state):
    print("call IORecursiveLockLock")
    lock = state.solver.eval(state.regs.rdi)
    # IORecursiveLock * _lock->thread = 0;
    thread = state.memory.load(lock+0x18, 8, endness=state.arch.memory_endness, inspect=False)
    curThread = state.memory.load(state.regs.gs+0x8, 8, endness=state.arch.memory_endness, inspect=False)
    print("thread:", thread, curThread)
    # state.memory.store(lock+0x18, state.solver.BVV(0, 64), inspect=False)
    # lock->count = 0
    count = state.memory.load(lock+0x20, 4, endness=state.arch.memory_endness, inspect=False)
    print("count:", count)
    # state.memory.store(lock+0x20, state.solver.BVV(0, 32), inspect=False)

class copyClientEntitlement(angr.SimProcedure):
    def run(self, task, entitlement):
        key = self.state.mem[entitlement].string.concrete.decode("utf8")
        print("call copyClientEntitlement", key)
        print("return kIOBooleanTrue", hex(self.state.globals["kIOBooleanTrue"]))
        if key not in getConfigKey("entitlements"):
            raise Exception("Unknown entitlement %s" % key)
        return self.state.globals["kIOBooleanTrue"]

class ReadRandom(angr.SimProcedure):
    def run(self, buf, count):
        size = self.state.solver.max_int(count)
        if size > MAX_MEMORY_SIZE: size = 1024
        ptr = self.state.solver.eval(buf)
        for i in range(size):
            b = random.randrange(256)
            self.state.memory.store(ptr+i, self.state.solver.BVV(b, 8))
        return count


class MacModel(BaseModel):
    def __init__(self):
        pass

    def getFunc2Model(self):
        funcWithZero = DummyModel()
        funcWithOne = DummyModel(ret_value=1)
        models = {
            "IOCommandGate::runAction": runAction(),
            "IOWorkLoop::runAction": IOWorkLoopRunAction(),
            "IOGeneralMemoryDescriptor::prepare": MemPrepare(),
            "IOMemoryDescriptor::writeBytes": MemWriteBytes(),
            "IOMemoryDescriptor::readBytes": MemReadBytes(),
            "IOGeneralMemoryDescriptor::initWithOptions": funcWithOne,
            "IOGeneralMemoryDescriptor::complete": funcWithZero,
            "IOMemoryDescriptor::makeMapping": MakeMapping(),
            "IOMemoryMap::getVirtualAddress": GetVirtualAddress(),
            "IOMemoryMap::getMemoryDescriptor": GetMemoryDescriptor(),
            "lck_mtx_lock": funcWithZero,
            "lck_mtx_lock_spin_always": funcWithZero,
            "lck_mtx_unlock": funcWithZero,
            "lck_spin_lock": funcWithZero,
            "lck_spin_unlock": funcWithZero,
            "lck_mtx_try_lock": funcWithOne,
            "lck_mtx_lock_spin": funcWithZero,
            "IOSimpleLockLock": funcWithZero,
            "IOSimpleLockUnLock": funcWithZero,
            "OSObject::release()": funcWithZero,
            "IOMalloc": IOMalloc(),
            "kalloc_canblock": KallocCanblock(),
            "zalloc": Zalloc(),
            "IOFree": funcWithZero,
            "kfree": funcWithZero,
            "zfree": funcWithZero,
            "bzero": bzero(),
            "memset": Memset(),
            "snprintf": Snprintf(),
            # "IORecursiveLockLock": IORecursiveLockLock,
            # "IORecursiveLockUnlock": funcWithZero,
            
            "__memmove_chk": MemmoveChk(),
            "memmove": Memmove(),
            "memcpy": Memmove(),
            "bcopy": Memmove(),
            "strnlen": Strnlen(),
            "IOLog": funcWithZero,
            "_os_log_internal": funcWithZero,
            "kprintf": funcWithZero,
            # "OSAddAtomic16": OSAddAtomic16(),
            "kernel_thread_start": KernelThreadStart(),
            "thread_wakeup_thread": ThreadWakeupThread(),
            "IOEventSource::signalWorkAvailable": DummyStub(ret_value=1),
            "IOTimerEventSource::setTimeout(unsigned int, unsigned int)": funcWithZero,
            "IOTimerEventSource::setTimeout(unsigned long long)": funcWithZero,
            "IOTimerEventSource::setTimeout(unsigned int, unsigned long long, unsigned long long)": funcWithZero,
            "IOCommandGate::commandWakeup": funcWithZero,
            "IOCommandGate::commandSleep(void*, unsigned int)": funcWithZero,
            "IOCommandGate::commandSleep(void*, unsigned long long, unsigned int)": funcWithZero,
            "mach_msg_send_from_kernel_proper": funcWithZero,

            "IOBufferMemoryDescriptor::initWithPhysicalMask": InitWithPhysicalMask(),
            "IOBufferMemoryDescriptor::setLength": IOBufferSetLength(),
            "IOBufferMemoryDescriptor::getBytesNoCopy()": IOBufferGetBytesNoCopy(),
            "IOBufferMemoryDescriptor::appendBytes": IOBufferAppendBytes(),

            "ml_io_read": funcWithZero,
            "clock_get_system_microtime": ClockGetTime(),
            "IOService::terminate": funcWithZero,

            "IOUserClient::copyClientEntitlement": copyClientEntitlement(),
            "read_random": ReadRandom(),

            # TODO: model OSDictionary properly
            "OSUnserializeXML(char const*, unsigned long, OSString**)": funcWithZero,

            "vnode_authorize": funcWithZero,
            "vprintf": funcWithZero,
            "tsleep": funcWithZero,
            'msleep': funcWithZero,

            "copyin": Copyin()
        }

        return models

    def getFunc2Hook(self):
        # Hook methods without replacing them
        hooks = {
            # "IOMalloc": IOMalloc
            "OSSymbol::withCStringNoCopy": OSSymbolString,
            "OSString::withCString": OSStringWithCString,
            "IORecursiveLockLock": IORecursiveLockLock
        }
        return hooks

