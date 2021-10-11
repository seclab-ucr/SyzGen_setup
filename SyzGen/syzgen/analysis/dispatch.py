
import logging
import angr
import subprocess
import time
import random

from claripy.ast.bv import Reverse, Extract
from angr.state_plugins.inspect import BP
from capstone.x86_const import X86_OP_REG, X86_OP_MEM, X86_OP_IMM

from ..executor.executor import Executor, MacExecutor
from ..parser.generate import genServicePoc
from ..kext.macho import Method, ExternalMethodDispatch, DispatchTable, parse_vtables, getAllClassFunctions, findVtableOffset
from ..utils import extractVariables, extractBaseOffset, getRemoteAddr, vmrun
from ..debugger.lldbproxy import setup_debugger
from ..debugger.proxy import ProxyException
from .static import analyze_getTargetAndMethodForIndex

logger = logging.getLogger(__name__)

# struct IOExternalMethod {
#     IOService *         object;
#     IOMethod            func;
#     IOOptionBits        flags;
#     IOByteCount         count0;
#     IOByteCount         count1;
# };

# struct IOExternalMethodDispatch {
#   IOExternalMethodAction function;
#   uint32_t               checkScalarInputCount;
#   uint32_t               checkStructureInputSize;
#   uint32_t               checkScalarOutputCount;
#   uint32_t               checkStructureOutputSize;
# };

def getDispatchMethod(executor, state, ptr, cmd, isCustom=False):
    """If we arrive parent's externalMethod, we could extract the argument according to its type (IOExternalMethodDispatch).
    Otherwise, we only retrieve the pointer.
    """
    addr = state.mem[ptr].uint64_t.resolved
    if isinstance(executor, Executor):  # dynamic execution
        _, offset = executor.getBaseAddr(state.solver.eval(addr), target=executor.target)
    else:  # static analysis
        offset = state.solver.eval(addr)
    if not offset:
        # it is possible we have a null pointer.
        return True, None

    sym = executor.proj.loader.find_symbol(offset)
    if not sym or sym.section_name != "__text":
        return False, None

    # FIX: the offset to the function, not the pointer
    # if isinstance(executor, Executor):
    #     _, relative_ptr = executor.getBaseAddr(ptr, target=executor.target)
    # else:
    #     relative_ptr = ptr

    if isCustom: # whether the table follows certain structure (ie, IOExternalMethodDispatch)
        return True, Method(offset, cmd, sym.name)
        # return Method(relative_ptr, cmd, sym.name)
    else:
        # FIXME: use memory.load to avoid redundent inspection
        scalarInputCount = state.solver.eval(state.mem[ptr+0x8].uint32_t.resolved)
        structInputSize = state.solver.eval(state.mem[ptr+0xc].uint32_t.resolved)
        scalarOutputCount = state.solver.eval(state.mem[ptr+0x10].uint32_t.resolved)
        structOutputSize = state.solver.eval(state.mem[ptr+0x14].uint32_t.resolved)
        return True, ExternalMethodDispatch(offset, cmd, sym.name, scalarInputCount=scalarInputCount, \
            structInputSize=structInputSize, scalarOutputCount=scalarOutputCount, structOutputSize=structOutputSize)


def parse_dispatchTable(executor, state, cmd, expr, isCustom=False):
    """We find a table for dispatching functions, and cmd is the index. Thus,
    we enumerate all possible value for index starting from 0 until we cannot
    find any more functions.
    """
    i = 0
    table = DispatchTable(cmd)
    # We directly assign symbolic value to registers when symbolizing selector. Otherwise,
    # cmd comes from nested structure is in big endian.
    isLittleEndian = cmd.op == "BVS" and cmd._encoded_name.startswith(b"selector")
    total = state.solver.max(cmd) if isLittleEndian else state.solver.max(Reverse(cmd))
    logger.debug("cmd max: %d" % total)
    if total > 1024:
        logger.info("probably there is a bug...")
    
    while i <= total:
        blank_state = executor.proj.factory.blank_state()
        if isLittleEndian:
            blank_state.solver.add(cmd == i)
        else:
            blank_state.solver.add(Reverse(cmd) == i)
        ptr = blank_state.solver.eval(expr)
        succeed, m = getDispatchMethod(executor, state, ptr, i, isCustom=isCustom)
        if not succeed:
            return None

        if m:
            table.addMethod(i, m)
        i += 1

    while True:
        # Due to concretization, we may have some unnecessary constraints.
        # We allow it to continue to search forward and halt if we cannot find more functions.
        # Typically the function table is followed by some null bytes.
        blank_state = executor.proj.factory.blank_state()
        if isLittleEndian:
            blank_state.solver.add(cmd == i)
        else:
            blank_state.solver.add(Reverse(cmd) == i)
        ptr = blank_state.solver.eval(expr)
        succeed, m = getDispatchMethod(executor, state, ptr, i, isCustom=isCustom)
        if not succeed or not m:
            break
        table.addMethod(i, m)
        i += 1

    print(table.repr())
    if table.size() > 1:
        return table
    return None

class ExecutorBP(BP):
    def __init__(self, when=angr.BP_BEFORE, executor=None):
        super(ExecutorBP, self).__init__(when=when)
        
        self.executor = executor
        
    def fire(self, state):
        if state.addr > 0xffffff8000000000:
            return

        print(state.inspect.mem_read_address, state.inspect.mem_read_length)
        if not state.solver.is_true(state.inspect.mem_read_length == 8):
            return

        expr = state.inspect.mem_read_address
        base, offset = extractBaseOffset(state, expr)
        if base is None or offset is None: return

        cmds = extractVariables(offset)
        if len(cmds) == 1:
            cmd = cmds[0]
            print("extract cmd from mem access:", cmd)
            table = parse_dispatchTable(self.executor, state, cmd, expr, isCustom=True)
            if table:
                self.executor.addTable(table)
                self.executor.abort()

class CallExternalMethod(angr.SimProcedure):
    # NO_RET = True

    def run(self, this, selector, args, dispatch, object, reference, executor=None):
        """IOUserClient::externalMethod(unsigned int, IOExternalMethodArguments*, IOExternalMethodDispatch*, OSObject*, void*)
        """
        print(selector, dispatch)
        logger.debug("call IOUserClient::externalMethod")
        if not self.state.solver.symbolic(dispatch):
            # probably only one dispatch function
            cmd = Extract(31, 0, selector.to_claripy())
            ptr = self.state.solver.eval(dispatch)
            if ptr == 0:  # It will invoke getTargetAndMethodForIndex
                # TODO: combine two dispatch tables!!
                return

            print("cmd:", cmd)
            print(self.state.solver.eval(cmd))

            table = DispatchTable(cmd)
            i = self.state.solver.min(cmd)
            _, m = getDispatchMethod(executor, self.state, ptr, i, isCustom=False)
            table.addMethod(i, m)
            executor.addTable(table)
        else:
            base, offset = extractBaseOffset(self.state, dispatch)
            if base is None or offset is None:
                logger.debug("base or offset is None")
                # <SAO <BV64 if 0x5 <= selector_0_32 then 0x0 else 0xffffff7f90833470 + 
                # ((0x0 .. selector_0_32) + (0x0 .. selector_0_32 .. 0) .. 0)>>
                if dispatch.op == 'If':
                    cond = dispatch.args[0]

                    cmds = extractVariables(dispatch)
                    if len(cmds) != 1:
                        print(cmds)
                        logger.error("retrieve %d cmds, expect 1" % len(cmds))
                        return
                    cmd = cmds[0]

                    table = None
                    max_cmd = self.state.solver.max(cmd, (cond, ))
                    min_cmd = self.state.solver.min(cmd, (cond, ))
                    if max_cmd - min_cmd < 1024:
                        self.state.solver.add(cond)
                        table = parse_dispatchTable(executor, self.state, cmd, dispatch.args[1], isCustom=False)
                    else:
                        max_cmd = self.state.solver.max(cmd, (cond != True, ))
                        min_cmd = self.state.solver.min(cmd, (cond != True, ))
                        if max_cmd - min_cmd < 1024:
                            self.state.solver.add(cond != True)
                            table = parse_dispatchTable(executor, self.state, cmd, dispatch.args[2], isCustom=False)

                    if table:
                        executor.addTable(table)
                        executor.abort()
                # from IPython import embed; embed()
            else:
                cmds = extractVariables(offset)
                if len(cmds) != 1:
                    print(cmds)
                    logger.error("retrieve %d cmds, expect 1" % len(cmds))
                    return

                cmd = cmds[0]
                table = parse_dispatchTable(executor, self.state, cmd, dispatch, isCustom=False)
                if table:
                    executor.addTable(table)
                    executor.abort()

class DispatchExecutor(MacExecutor):
    def __init__(self, proxy, binary, kext, service, client, entry, no_mem=False):
        MacExecutor.__init__(self, proxy, binary, kext, entry, isConcolic=False)

        self._random = random.Random()
        self._random.seed(10)

        self.tables = []

        # possible functionalities
        self.target_addrs = set()
        self.service = service
        self.client = client
        metaClazz = parse_vtables(self.proj)
        self.service.meta = metaClazz[service.metaClass]
        self.client.meta = metaClazz[client.metaClass]
        # consider all class functions (excluding some default functions)
        for sym in getAllClassFunctions(self.proj):
            self.target_addrs.add(self.target_base + sym.relative_addr)
        # for sym in getClassFunctions(self.proj, service.metaClass):
        #     self.target_addrs.add(self.target_base + sym.relative_addr)
        # for sym in getClassFunctions(self.proj, client.metaClass):
        #     self.target_addrs.add(self.target_base + sym.relative_addr)


        # options
        self._no_mem = no_mem

    def pre_execute(self, state):
        # externalMethod(this, uint32_t selector, IOExternalMethodArguments * args,
        #    IOExternalMethodDispatch * dispatch, OSObject * target, void * reference )
        args = state.regs.rdx
        selector = state.regs.esi
        scalarInput = state.mem[args+0x20].uint64_t.resolved  # args->scalarInput
        scalarInputCount = state.mem[args+0x28].uint32_t.resolved # args->scalarInputCount
        structInput = state.mem[args+0x30].uint64_t.resolved   # args->structureInput
        structInputSize = state.mem[args+0x38].uint32_t.resolved   # args->structureInputSize
        scalarOutput = state.mem[args+0x48].uint64_t.resolved  # args->scalarOutput
        scalarOutputCount = state.mem[args+0x50].uint32_t.resolved  # args->scalarOutputCount
        structOutput = state.mem[args+0x58].uint64_t.resolved  # args->structureOutput
        structOutputSize = state.mem[args+0x60].uint32_t.resolved  # args->structureOutputSize
        print("selector", selector)
        print("scalarInput*", scalarInput)
        print("scalarInputCount", scalarInputCount)
        print("structInput*", structInput)
        print("structInputSize", structInputSize)
        print("scalarOutput*", scalarOutput)
        print("scalarOutputCount", scalarOutputCount)
        print("structOutput", structOutput)
        print("structOutputSize", structOutputSize)

        # FIXME: add constraints to structInputSize/structOutputSize, otherwise we may encounter OOB read/write
        # when we have symbolic index involving them. Note that we detect cmd handler by checking common variables
        # so that we must rule out these special variables (we assume they can not be cmd handler).
        sym_selector = state.solver.BVS("selector", 32, key=("selector", 4), eternal=True)
        state.regs.esi = sym_selector
        state.mem[args+0x4].uint32_t = state.regs.esi    # selector is also stored in args
        # default count for scalar input is 6
        sym_scalarInputCount = state.solver.BVS("scalarInputCount", 32, key=("scalarInputCount", 4), eternal=True)
        sym_scalarInput = state.solver.BVS("scalarInput", 16*8*8, key=("scalarInput", 24), eternal=True)
        state.memory.store(args+0x28, sym_scalarInputCount)
        addr = state.solver.eval(scalarInput)
        state.memory.store(addr, sym_scalarInput)
        # default size for input buffer is 1024 bytes
        sym_structInputSize = state.solver.BVS("structInputSize", 32, key=('structInputSize', 4), eternal=True)
        sym_structInput = state.solver.BVS("structInput", 1024 * 8, key=('structInput', 1024), eternal=True)
        state.memory.store(args+0x38, sym_structInputSize)
        addr = state.solver.eval(structInput)
        state.memory.store(addr, sym_structInput)
        # No need to symbolize output buffer
        sym_scalarOutputCount = state.solver.BVS("scalarOutputCount", 32, key=('scalarOutputCount', 4), eternal=True)
        sym_structOutputSize = state.solver.BVS("structOutputSize", 32, key=('structOutputSize', 4), eternal=True)
        state.memory.store(args+0x50, sym_scalarOutputCount)
        state.memory.store(args+0x60, sym_structOutputSize)

        if not self._no_mem:
            # setup breakpoints to inspect memory access
            bp = ExecutorBP(when=angr.BP_BEFORE, executor=self)
            state.inspect.add_breakpoint('mem_read', bp)

        addr = self.getFuncAddr("IOUserClient::externalMethod")
        self.proj.hook(addr, CallExternalMethod(executor=self), length=0)

    def addTable(self, table):
        self.tables.append(table)

    def getDispatchTable(self):
        if len(self.tables) == 0:
            logger.error("failed to find any dispatch table")
            return None
        elif len(self.tables) > 1:
            logger.error("has more than one dispatch tables")
            for table in self.tables:
                print(table.repr())

        return self.tables[0]

    def execute(self, simgr):
        # target = 0x11a16 + self.target_base
        # DFS exploration adopted from angr.exploration_techniques.DFS
        simgr.stashes["deferred"] = []
        simgr.stashes["barrier"] = []
        while not self.should_abort:
            print(hex(simgr.active[0].addr), len(simgr.deferred), len(simgr.barrier))
            # if simgr.active[0].addr == target:
            #     break

            simgr = simgr.step()
            simgr.move(from_stash="active", to_stash="barrier", filter_func=lambda s: s.addr in self.target_addrs)
            if len(simgr.active) > 1:
                self._random.shuffle(simgr.active)
                simgr.split(from_stash="active", to_stash="deferred", limit=1)

            if len(simgr.active) == 0:
                if len(simgr.stashes["deferred"]) == 0:
                    if self.detect_cmd_handler(simgr):
                        break
                    continue
                simgr.active.append(simgr.stashes["deferred"].pop())

        return simgr

    def detect_cmd_handler(self, simgr):
        size = len(simgr.stashes["barrier"])
        if size == 0:
            # break
            return True

        logger.debug("[detect_cmd_handler] state addresses:")
        addr = simgr.barrier[0].addr
        logger.debug(hex(addr))
        same_addr = True
        for state in simgr.barrier[1:]:
            logger.debug(hex(state.addr))
            if state.addr != addr:
                same_addr = False
                break
        if same_addr:
            # continue
            simgr.move(from_stash="barrier", to_stash="active")
            return False

        # collect common symbolic variables
        variables = []
        for state in simgr.barrier:
            candidates = extractVariables(state.solver.constraints)
            variables.append(candidates)

        def inBlacklist(name):
            if name.startswith(b"scalarInputCount"):
                return True
            if name.startswith(b"structInputSize"):
                return True
            if name.startswith(b"scalarOutputCount"):
                return True
            if name.startswith(b"structOutputSize"):
                return True
            return False

        common_vars = dict()
        for sym in variables[0]:
            # Those variables may exist in all states but cannot be cmd handler.
            print("common var:", sym)
            if sym.op == "BVS":
                if inBlacklist(sym._encoded_name):
                    continue
            common_vars[sym] = True

        for arr in variables[1:]:
            new_vars = dict()
            arr = dict([(sym, True) for sym in arr])
            # check if previously common variables are used in another state
            for sym in common_vars:
                if sym in arr:
                    new_vars[sym] = True
            common_vars = new_vars

        # check each of them
        print("common_vars:", common_vars)
        for var in common_vars:
            print(var)
            vals = set()
            found = True
            for state in simgr.barrier:
                v = state.solver.min(var)
                if v in vals and v != state.solver.max(var):
                    # for each case the corresponding cmd value must be different unless
                    # we know that selector has only one possible value.
                    # Duplicate: 
                    # if inputStruct == NULL {
                    # 
                    # } else {}
                    # 
                    # two states can reach the same spot and thus we have duplicated v.
                    found = False
                    break
                vals.add(v)

            if found and len(vals) > 1:
                print("cmd handler is", var, vals)
                # Each state should has one specific cmd handler
                remained, moved = [], []
                for state in simgr.barrier:
                    _max = state.solver.max(var)
                    _min = state.solver.min(var)
                    if _min != _max:
                        moved.append(state)
                    else:
                        remained.append(state)
                if len(moved) > 0:
                    # TODO: for switch cases, one state can correspond to multiple command handlers.
                    logger.debug("It is still worth further exploration, continue...")
                    simgr._clear_states("barrier")
                    simgr._store_states("active", moved)
                    simgr._store_states("barrier", remained)
                    return False

                # create dispatch table
                table = DispatchTable(var)
                if var.op != "BVS":
                    var = Reverse(var)
                for state in simgr.barrier:
                    _, offset = self.getBaseAddr(state.addr, self.target)
                    sym = self.proj.loader.find_symbol(offset)
                    if sym is None:
                        return False

                    # FIX: use the offset to the function not the pointer as we don't need hook anymore.
                    # find the address in vtable to hook (0 if it is a regular function)
                    # off = findVtableOffset(self.service.meta, sym.name) or \
                    #     findVtableOffset(self.client.meta, sym.name)
                    cmd = state.solver.min(var)
                    m = Method(offset, cmd, sym.name)
                    # m = Method(off, cmd, sym.name)
                    table.addMethod(cmd, m)

                print(table.repr())
                self.addTable(table)
                self.abort()
                return True

        print("We may need to take a look at it!!!!!")
        for state in simgr.barrier:
            print(hex(state.addr))
        return False

def _find_dispatchTable(proxy, binary, kext, service, client, no_mem=False):
    """Make sure the VM is running and not stuck.
    """
    if not client.externalMethod:
        # use static analysis to get dispatch table from getTargetAndMethodForIndex
        return analyze_getTargetAndMethodForIndex(binary, service, client)

    # Generate testcase that will trigger externalMethod
    genServicePoc(service.metaClass, client)
    remote_addr = getRemoteAddr()
    # copy PoC to guest
    subprocess.run(["scp", "poc", "%s:./" % remote_addr], check=True)
    logger.debug("copy PoC to guest")

    thread, lock = setup_debugger()
    try:
        with proxy:
            logger.debug("set breakpoint for %s at 0x%x" % (kext, client.externalMethod))
            proxy.set_breakpoint(kext, client.externalMethod)

            # make sure the vm is not stuck
            proxy.clear()

            # run poc
            if client.access:
                subprocess.run(["ssh", remote_addr, "~/poc"])
            else:
                subprocess.run(["ssh", remote_addr, "sudo ~/poc"])
            logger.debug("execute the PoC in guest")

            # TODO: check inputs to make sure it is the correct one.
            proxy.wait_breakpoint()
            # lldb use int3 to realize breakpoint. To get around this instruction, we need
            # to step forward.
            # proxy.step()
            # Remove all breakpoints (recover from int3)
            proxy.remove_breakpoints()

            executor = DispatchExecutor(proxy, binary, kext, service, client, client.externalMethod, \
                no_mem=no_mem)
            executor.run()

            return executor.getDispatchTable()
    finally:
        lock.release()
        time.sleep(10)
        logger.debug("terminate debugger")
        thread.terminate()

        vmrun("reset")
        time.sleep(60)


def find_dispatchTable(proxy, binary, kext, service, client, no_mem):
    """ A wrapper for the real function in order to capture exception and retry.
    """
    while True:
        try:
            return _find_dispatchTable(proxy, binary, kext, service, client, no_mem)
        except ProxyException as e:
            logger.error("proxy error occurs! retrying...")
