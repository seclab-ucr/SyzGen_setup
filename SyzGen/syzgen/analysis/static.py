
import angr
import traceback
import logging

from angr.analyses.forward_analysis import ForwardAnalysis
from angr.analyses.cfg.cfg_job_base import CFGJobBase
from angr.analyses import Analysis
from capstone.x86_const import X86_OP_MEM, X86_OP_IMM, X86_OP_REG
from claripy.ast.bv import Reverse
from angr.state_plugins.inspect import BP

from ..kext.macho import UserClient, Service, check_effect_client, read_vtables, DispatchTable, \
	analyze_dispatchMethods, parse_vtables, find, isDefinedFunc, check_effect_service
from ..kext.helper import parse_signature, DbgHelper
from ..utils import demangle, extractVariables, extractBaseOffset, demangle, extractSymbol
from ..executor.executor import StaticExecutor

logger = logging.getLogger(__name__)

class AnalysisBP(BP):
    """struct IOExternalMethod {
        IOService *         object;
        IOMethod            func;  # sizeof(IOMethod) == 0x10
        IOOptionBits        flags;
        IOByteCount         count0;
        IOByteCount         count1;
    };"""
    def __init__(self, when=angr.BP_BEFORE, executor=None):
        super(AnalysisBP, self).__init__(when=when)
        
        self.executor = executor

    def fire(self, state):
        print(state.inspect.mem_read_address, state.inspect.mem_read_length)
        if not state.solver.is_true(state.inspect.mem_read_length == 8):
            return

        expr = state.inspect.mem_read_address
        base, offset = extractBaseOffset(state, expr)
        if base is None or offset is None: return

        cmds = extractVariables(offset)
        print(cmds)
        if len(cmds) == 1:
            cmd = cmds[0]
            i = 0
            table = DispatchTable(cmd)
            while True:
                blank_state = self.executor.proj.factory.blank_state()
                blank_state.solver.add(Reverse(cmd) == i)
                ptr = blank_state.solver.eval(expr)
                addr = state.mem[ptr+0x8].uint64_t.resolved
                flags = state.mem[ptr+0x18].uint64_t.resolved
                count0 = state.mem[ptr+0x20].uint64_t.resolved
                count1 = state.mem[ptr+0x28].uint64_t.resolved
                offset = state.solver.eval(addr)

                print(ptr, i, offset)
                sym = self.executor.proj.loader.find_symbol(offset)
                if not sym or sym.section_name != "__text":
                    break

                table.addExternalMethod(ptr, i, sym.name, state.solver.eval(flags), \
                    state.solver.eval(count0), state.solver.eval(count1))
                print(i, hex(offset), sym)
                i += 1

            # print(table.repr())
            print("table size: %d" % table.size())
            if table.size() > 1:
                self.executor.addTable(table)
                self.executor.abort()

class EntitlementExecutor(StaticExecutor):
    """IOUserClient::copyClientEntitlement(task, const char*)
    """

    MAXIMUM_TIMES = 5

    def __init__(self, binary, func, start):
        super(EntitlementExecutor, self).__init__(binary, func, start)

        self.entitlement = ""
        self.counters = dict()

    def execute(self, state):
        """ Record the excution times of each basic block to avoid running indefinitely.
        """
        if state.addr not in self.counters:
            self.counters[state.addr] = 1
        else:
            self.counters[state.addr] += 1
        if self.counters[state.addr] > self.MAXIMUM_TIMES:
            return []

        return super(EntitlementExecutor, self).execute(state)

    def handle_state(self, state, block):
        print(hex(state.addr), hex(block.addr))
        if block.capstone.insns[-1].mnemonic == 'call':
            addr = block.capstone.insns[-1].address + 1
            if addr in self.proj.loader.main_object.extreltab:
                idx = self.proj.loader.main_object.extreltab[addr].referenced_symbol_index
                sym = self.proj.loader.main_object.get_symbol_by_insertion_order(idx)
                print("call %s" % sym.name)
                metaClass, func = parse_signature(demangle(sym.name))
                if metaClass == "IOUserClient" and func == "copyClientEntitlement":
                    entitlement = state.mem[state.regs.rsi].string.concrete.decode("utf8")
                    print("require entitlement: %s" % entitlement)
                    self.entitlement = entitlement
                    self.abort()
                

def find_entitlement(binary):
    entitlements = set()
    proj = angr.Project(binary)
    targets = ["initWithTask", "newUserClient"]  # possible functions that will check entitlements
    for tgt in targets:
        for sym in find(proj, tgt):
            if sym.section_name != "__text":
                continue
            metaClass, func = parse_signature(demangle(sym.name))
            if func != tgt:
                continue

            print(metaClass, func, sym.name, sym.relative_addr)
            executor = EntitlementExecutor(binary, sym, sym.relative_addr)
            executor.run()
            if executor.entitlement:
                entitlements.add(executor.entitlement)

    return entitlements

# def onConstraint(state):
#     for each in state.inspect.added_constraints:
#         if state.solver.eval(each) == False:
#             return

#     print("onConstraint:", state.regs.rip)
#     if state.solver.symbolic(state.regs.rip):
#         sym, _, _ = extractSymbol(state.regs.rip)
#         if sym._encoded_name.startswith(b'selector_'):
#             candidates = state.solver.eval_upto(state.regs.rip, 256)
#             for addr in candidates:
#                 copy_state = state.copy()
#                 copy_state.solver.add(state.regs.rip == addr)
#                 cmd = copy_state.solver.eval(Reverse(sym))
#                 print("ptr", hex(addr), cmd)

#                 state.globals["table"][cmd] = addr

#             state.locals["halt"] = True
#     else:
#         for each in state.inspect.added_constraints:
#             print(each)
#             sym, _, _ = extractSymbol(each)
#             if sym._encoded_name.startswith(b'selector_'):
#                 _min = state.solver.min(Reverse(sym))
#                 _max = state.solver.max(Reverse(sym))
#                 print("selector min: %d, max: %d" % (_min, _max))
#                 if _min == _max:
#                     state.globals["table"][_min] = state.addr
#                     state.locals["halt"] = True
#                     break

class StaticDispatchExecutor(StaticExecutor):
    """
    externalMethod(this, uint32_t selector, IOExternalMethodArguments * args,
           IOExternalMethodDispatch * dispatch, OSObject * target, void * reference )
    """
    def __init__(self, binary, func, start, service=None, client=None):
        super(StaticDispatchExecutor, self).__init__(binary, func, start)

        self.service = service
        self.client = client

    def getInitState(self):
        state = super(StaticDispatchExecutor, self).getInitState()
        self.initState = state

        args = 0xb0004000
        sym_selector = state.solver.BVS("selector", 32, key=("selector", 4), eternal=True)
        state.regs.esi = sym_selector
        state.mem[args+0x4].uint32_t = state.regs.esi    # selector is also stored in args

        vtables = read_vtables(self.proj, self.metaClazz[self.client.metaClass])
        client = state.solver.BVS("client", 0x1000*8)
        # First field is vtable
        state.memory.store(0xb0000000, state.solver.BVV(0xb0001000, 64), endness=state.arch.memory_endness)
        state.memory.store(0xb0000008, client)
        state.memory.store(0xb0001000, state.solver.BVV(vtables, len(vtables)*8))

        # state.inspect.b('constraints', when=angr.BP_BEFORE, action=onConstraint)
        # We assume it always uses the selector from the parameter.
        self.table = DispatchTable(sym_selector)
        self.groups = list()

        return self.proj.factory.call_state(state.addr, 0xb0000000, sym_selector, args, 0, 0, 0, base_state=state)

    def handle_state(self, state, block):
        _min = state.solver.min(Reverse(self.table.sym))
        _max = state.solver.max(Reverse(self.table.sym))
        if _min == _max:
            self.table.addCustomMethod(state.addr, _min, "externalMethod_%d" % _min)
            self.groups.append(({_min}, state.addr))
            return True

        # Record potential cmds
        # TODO: if we assume one cmd can only correspond to one functionality and vice versa,
        # comment the following code.
        if _max - _min < 128:
            candidates = state.solver.eval_upto(Reverse(self.table.sym), 128)
            self.groups.append((set(candidates), state.addr))

    def post_execute(self):
        # find all command handlers
        cmds = set()
        for group in self.groups:
            for each in group[0]:
                cmds.add(each)

        # for each command handler, choose the group with the smallest size.
        parents = dict()
        for cmd in cmds:
            smallest = None
            for group in self.groups:
                if cmd in group[0]:
                    if smallest is None or len(smallest[0]) > len(group[0]):
                        smallest = group
            parents[cmd] = smallest

        for group in parents.values():
            found = False
            for each in group[0]:
                if each in self.table.methods:
                    found = True
                    break
            if not found:
                # None of its member is recovered.
                self.table.addCustomMethod(group[1], min(group[0]), "externalMethod_%d" % min(group[0]))

    def getDispatchTable(self):
        if self.table.size():
            return self.table
        return None

class TargetExecutor(StaticExecutor):
    """Method * getTargetAndMethodForIndex(IOService **targetP, UInt32 index);
    Analyzing the above function to get the dispatch table.
    """
    def __init__(self, binary, func, start, service=None, client=None):
        super(TargetExecutor, self).__init__(binary, func, start)

        self.service = service
        self.client = client

        self.table = None

    def getInitState(self):
        state = super(TargetExecutor, self).getInitState()

        vtables = read_vtables(self.proj, self.metaClazz[self.client.metaClass])
        client = state.solver.BVS("client", 0x1000*8)
        index = state.solver.BVS("selector", 32, key=("getTargetAndMethodForIndex", "selector"), eternal=True)

        self.table = DispatchTable(index) # second argument must be the cmd.
        # First field is vtable
        state.memory.store(0xb0000000, state.solver.BVV(0xb0001000, 64), endness=state.arch.memory_endness)
        state.memory.store(0xb0000008, client)
        state.memory.store(0xb0001000, state.solver.BVV(vtables, len(vtables)*8))
        state.memory.store(0xb0002000, state.solver.BVV(0, 64))
        return self.proj.factory.call_state(state.addr, 0xb0000000, 0xb0002000, index, base_state=state)

    def getServiceFunc(self, obj, func):
        """
        IOMethod: disassemble -n shim_io_connect_method_scalarI_structureI
        0xffffff801f9f626e <+78>:  movq   0x8(%r15), %r11   ; r11 = func
        0xffffff801f9f6272 <+82>:  movq   0x10(%r15), %rcx  ; rcx = offset
        ... ... 
        0xffffff801f9f6286 <+102>: addq   %rcx, %rsi        ; rsi = object + offset
        0xffffff801f9f6289 <+105>: testb  $0x1, %r11b
        0xffffff801f9f628d <+109>: je     0xffffff801f9f6297        ; <+119> at IOUserClient.cpp:5275:10
        0xffffff801f9f628f <+111>: movq   (%rsi), %rax
        0xffffff801f9f6292 <+114>: movq   -0x1(%r11,%rax), %r11
        """
        meta = self.metaClazz[obj.metaClass]
        if func&0x1:
            func = (func-1)//8
            return meta.vtables[func][1]
        else:
            sym = self.proj.loader.find_symbol(func)
            return sym.name

    def getService(self, state):
        """getTargetAndMethodForIndex returns the dispatch func and the second argument stores the corresponding
        service object. There are two possible service objects, one is the current client and the other one is
        the corresponding service.
        """
        service = state.mem[0xb0002000].uint64_t.resolved
        if state.solver.is_true(service == 0xb0000000):
            return self.client
        # FIXME: it is not guaranteed.
        return self.service

    def handle_state(self, state, block):
        """struct IOExternalMethod {
            IOService *         object;
            IOMethod            func;
            IOOptionBits        flags;
            IOByteCount         count0;
            IOByteCount         count1;
        };
        """
        # print("handle 0x%x 0x%x" % (state.addr, block.addr))
        isRet = False if block is None else block.capstone.insns[-1].mnemonic == "ret"
        if not isRet: return

        expr = state.regs.rax
        print("ret value:", expr)
        if not state.solver.symbolic(expr):
            # Probably only one dispatch function
            pass
        else:
            service = self.getService(state)
            candidates = state.solver.eval_upto(expr, 256)
            for addr in candidates:
                copy_state = state.copy()
                copy_state.solver.add(expr == addr)
                cmd = copy_state.solver.eval(Reverse(self.table.sym))
                print("ptr", hex(addr), cmd)

                func = copy_state.solver.eval(copy_state.mem[addr+0x8].uint64_t.resolved)
                flags = copy_state.solver.eval(copy_state.mem[addr+0x18].uint64_t.resolved)
                count0 = copy_state.solver.eval(copy_state.mem[addr+0x20].uint64_t.resolved)
                count1 = copy_state.solver.eval(copy_state.mem[addr+0x28].uint64_t.resolved)
                print(hex(func), flags, count0, count1)
                self.table.addExternalMethod(addr, cmd, self.getServiceFunc(service, func), flags, count0, count1)

    def getDispatchTable(self):
        return self.table


def findServices(proj, runInVM=True):
    """
    virtual IOReturn newUserClient( task_t owningTask, void * securityID,
        UInt32 type, OSDictionary * properties,
        LIBKERN_RETURNS_RETAINED IOUserClient ** handler );

    virtual IOReturn newUserClient( task_t owningTask, void * securityID,
        UInt32 type,
        LIBKERN_RETURNS_RETAINED IOUserClient ** handler );

    The second function is called first, if it is not overriden, the former one will be invoked.
    """
    symbols = []
    for sym in find(proj, "newUserClient"):
        if isDefinedFunc(sym):
            symbols.append(sym)
    
    services = dict()
    for sym in symbols:
        demangled = demangle(sym.name)
        metaClass, funcName = parse_signature(demangled)
        if funcName != "newUserClient":
            # check method name
            continue
        if metaClass in services:
            # multiple newUserClient seen
            # check signature
            signature = demangled[demangled.index("(")+1:-1]
            if len(signature.split(",")) == 4:
                continue

        service = Service(metaClass)
        service.newUserClient = sym.relative_addr
        if check_effect_service(service.metaClass, runInVM=runInVM, root=False):
            service.access = True
        elif check_effect_service(service.metaClass, runInVM=runInVM, root=True):
            service.access = False
        else:
            # Probably the module is not loaded!
            continue

        services[metaClass] = service
    return services

def parse_service(binary, clazz):
    """
    virtual IOReturn newUserClient( task_t owningTask, void * securityID,
        UInt32 type, OSDictionary * properties,
        LIBKERN_RETURNS_RETAINED IOUserClient ** handler );

    virtual IOReturn newUserClient( task_t owningTask, void * securityID,
        UInt32 type,
        LIBKERN_RETURNS_RETAINED IOUserClient ** handler );

    The second function is called first, if it is not overriden, the former one will be invoked.
    """
    proj = angr.Project(binary)
    service = Service(clazz)
    if check_effect_service(clazz, runInVM=True, root=False):
        service.access = True
    elif check_effect_service(clazz, runInVM=True, root=True):
        service.access = False
    else:
        logger.debug("Cannot access service: %s" % clazz)

    symbols = []
    for sym in find(proj, "newUserClient"):
        if isDefinedFunc(sym): # and sym.is_external:
            symbols.append(sym)

    for sym in symbols:
        demangled = demangle(sym.name)
        metaClass, funcName = parse_signature(demangled)
        if funcName != "newUserClient" or metaClass != service.metaClass:
            continue
        
        if service.newUserClient != 0:
            # multiple newUserClient seen
            # check signature
            signature = demangled[demangled.index("(")+1:-1]
            if len(signature.split(",")) == 4:
                continue

        service.newUserClient = sym.relative_addr

    return service

def parse_client(proj, client):
    symbols = []
    for sym in find(proj, client.metaClass):
        if isDefinedFunc(sym):  # and sym.is_external:
            symbols.append(sym)

    founded = 0
    for sym in symbols:
        demangled = demangle(sym.name)
        metaClass, funcName = parse_signature(demangled)
        if metaClass != client.metaClass:
            continue
        founded += 1
        if funcName == "externalMethod":
            client.externalMethod = sym.relative_addr
        elif funcName == "getTargetAndMethodForIndex":
            client.getTargetAndMethodForIndex = sym.relative_addr
        elif funcName == "getAsyncTargetAndMethodForIndex":
            client.getAsyncTargetAndMethodForIndex = sym.relative_addr
        elif funcName == "getTargetAndTrapForIndex":
            client.getTargetAndTrapForIndex = sym.relative_addr
    return founded > 0

# def findUserClient(proj, services):
#     for service in services.values():
#         # if service.metaClass != "IOBluetoothHCIController":
#         #     continue

#         print(service.repr())

#         sym = proj.loader.find_symbol(service.newUserClient)
#         lldb = DbgHelper(proj.filename)
#         size = lldb.getFuncSize(proj, sym)
#         vsa = proj.analyses.VSA(meta=service.meta, start=sym.relative_addr, end=sym.relative_addr+size,
#             prepare_init_state=prepare_initial_state, selector="findUserClient")
#         for client, typ in vsa.userClients.items():
#             userClient = UserClient(className=client, type=typ)
#             if check_effect_client(service.metaClass, typ):
#                 userClient.access = True
#             service.userClients.append(userClient)
#     return services

# def analyze_externalMethods(proj, client):
#     if client.externalMethod:
#         sym = proj.loader.find_symbol(client.externalMethod)
#         lldb = DbgHelper(proj.filename)
#         size = lldb.getFuncSize(proj, sym)
#         vsa = proj.analyses.VSA(meta=client.meta, start=sym.relative_addr, end=sym.relative_addr+size, 
#             prepare_init_state=prepare_externalMethod_state, selector="findDispatchMethod")
#         client.dispatchMethods = dict(vsa.externalMethods)

def analyze_externalMethod(binary, service, client):
    if client.externalMethod:
        proj = angr.Project(binary)
        func = find(proj, client.externalMethod, fuzzy=False)[0]
        executor = StaticDispatchExecutor(binary, func, client.externalMethod, service=service, client=client)
        executor.run()

        return executor.getDispatchTable()

    return None

def analyze_getTargetAndMethodForIndex(binary, service, client):
    if client.getTargetAndMethodForIndex:
        proj = angr.Project(binary)
        func = find(proj, client.getTargetAndMethodForIndex, fuzzy=False)[0]
        executor = TargetExecutor(binary, func, client.getTargetAndMethodForIndex, service=service, client=client)
        executor.run()
        
        print(executor.table.repr())
        return executor.table
    return None

# def analyze_kext(binary):
#     # /Users/CwT/Documents/debug/IOBluetoothFamily
#     proj = angr.Project(binary)
#     metaClazz = parse_vtables(proj)

#     # find services with function newUserClient
#     services = findServices(proj)
#     for service in services.values():
#         if service.metaClass in metaClazz:
#             service.meta = metaClazz[service.metaClass]

#     # find UserClient
#     findUserClient(proj, services)
#     for service in services.values():
#         for client in service.userClients:
#             if client.metaClass in metaClazz:
#                 client.meta = metaClazz[client.metaClass]
#             # locate key functions like externalMethods
#             parse_client(proj, client)

#     # testing only
#     # for service in services.values():
#     #     for client in service.userClients:
#     #         if client.metaClass == "IOBluetoothRFCOMMConnectionUserClient":
#     #             analyze_getTargetAndMethodForIndex(proj, client)

#     # find dispatch table from const array
#     analyze_dispatchMethods(proj, services)
#     for service in services.values():
#         for client in service.userClients:
#             if not client.access:
#                 continue

#             if client.meta and len(client.dispatchMethods) == 0:  # no dispatch table found in const section
#                 if client.externalMethod:
#                     analyze_externalMethods(proj, client)
#                 elif client.getTargetAndMethodForIndex:
#                     analyze_getTargetAndMethodForIndex(proj, client)

#     for service in services.values():
#         print(service.repr())
#     return services

# angr.AnalysesHub.register_default('VSA', VSA)
