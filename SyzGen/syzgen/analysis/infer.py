
import logging
import traceback
import os
import subprocess
import json
import angr
import time
import heapq
import re

from collections import defaultdict
from claripy.ast.bv import Reverse, Extract
from pexpect.exceptions import TIMEOUT
from pathlib import Path

from .explore import TargetException

from ..executor.executor import Executor, MacExecutor
from ..utils import (
    dumps,
    get_tmp_var,
    loads,
    getConfigKey,
    copy2vm,
    extractFields,
    extractSymbols,
    vmrun,
    getRemoteAddr,
    addEntitlement,
    access_tree
)
from ..config import ModelPath, ServicePath, TestCasePath, ResourcePath, PoCPath, Options
from ..debugger.lldbproxy import LLDBDebugger, LLDBProxy, run_debugger
from ..debugger.proxy import ProxyException
from ..parser.generate import generateTemplate, build_template, generateTestcases, generateConfig, buildPocFromSyz
from ..parser.symtype import SymType
from ..parser.types import PtrType, Type, Constant
from ..parser.interface import Argument
from ..parser.optimize import Context, reduce_syscalls, reduce_length, refine_buffer
from ..kext.macho import find

logger = logging.getLogger(__name__)
options = Options()

# Hierarchical agglomerative clustering
class Group:
    def __init__(self):
        self.points = []
        self.left = None
        self.right = None
    
    def getValue(self):
        return sum([v for _, v in self.points])/len(self.points)

def clustering(points):
    groups = []
    for k, v in points:
        g = Group()
        g.points.append((k, v))
        groups.append(g)
        
    def getClosestGroups(groups):
        heap = []
        for i in range(len(groups)):
            for j in range(i+1, len(groups)):
                dist = abs(groups[i].getValue() - groups[j].getValue())
                heapq.heappush(heap, (dist, i, j))
                
        _, i, j = heapq.heappop(heap)
        return i, j
    
    while len(groups) > 1:
        i, j = getClosestGroups(groups)
        print("merging", i, j)
        g = Group()
        for each in groups[i].points:
            g.points.append(each)
        for each in groups[j].points:
            g.points.append(each)
        g.left = groups[i]
        g.right = groups[j]
        groups[i] = g
        del groups[j]
        
    return groups[0]

def getGroupAddrs(root):
    addrs = set()
    for state, _ in root.points:
        addrs.update(state.locals.get("visited", set()))
    return addrs

def canRemove(a, b):
    # FIXME: we may not want to use a hard-coded threshold.
    if b.getValue()/2 > a.getValue(): # and a.getValue() < 200:
        addr1 = getGroupAddrs(a)
        addr2 = getGroupAddrs(b)
        for addr in addr1:
            if addr not in addr2:
                return False
        return True
    return False

def prune(root):
    # FIXME: bottom-up or top-down?
    if root.right and root.left:
        if canRemove(root.left, root.right):
            root.left = None
        elif canRemove(root.right, root.left):
            root.right = None
            
        new_points = []
        if root.left:
            prune(root.left)
            new_points += list(root.left.points)
        if root.right:
            prune(root.right)
            new_points += list(root.right.points)
        root.points = new_points
        
    return root

def remove_error_syscall(syscalls):
    points = [(each, each.numOfBB) for each in syscalls]
    print("total syscalls:", points)
    root = clustering(points)
    root = prune(root)
    print("remaining syscalls:", root.points)
    return [call for call, _ in root.points]

def onSymbolicRead(state):
    # some lib call like bcopy will access single byte
    if state.addr > 0xffffff8000000000:
        return
    
    print("on Memory Read", state.inspect.mem_read_address, state.inspect.mem_read_length)
    cont = state.memory.load(state.inspect.mem_read_address, state.inspect.mem_read_length, \
        endness=state.arch.memory_endness, disable_actions=True, inspect=False)
    '''
    on Memory Read <BV64 0xffffff7f82c2daa8> 8

    on Memory Read <BV64 Reverse(tmp_ffffff7f82c2daa8_13_64) + 0x8> 8
    onConstraint <BV64 0xffffff7f82b2c5f9> (<Bool Reverse(tmp_ffffff7f82c2daa8_13_64) + 0x8 == 0xffffff8008e69ba8>,)

    on Memory Read <BV64 Reverse(tmp_ffffff8008e69ba8_17_64) + 0xd0> 8
    onConstraint <BV64 0xffffff7f82ba05f0> (<Bool Reverse(tmp_ffffff8008e69ba8_17_64) + 0xd0 == 0xffffff80085ab2d0>,)

    on Memory Read <BV64 Reverse(tmp_ffffff80085ab2d0_21_64) + ((0#32 .. (inputStruct_1_32[7:0] .. inputStruct_1_32[15:8] .. inputStruct_1_32[23:16] .. inputStruct_1_32[31:24])) << 0x3) + 0xb8> 8
    onConstraint <BV64 0xffffff7f82ba060f> (<Bool Reverse(tmp_ffffff80085ab2d0_21_64) + ((0#32 .. (inputStruct_1_32[7:0] .. inputStruct_1_32[15:8] .. inputStruct_1_32[23:16] .. inputStruct_1_32[31:24])) << 0x3) + 0xb8 == 0xffffff8008f360e0>,)
    '''
    if options.infer_dependence and not state.solver.symbolic(cont):
        # if config.MEM_ACCESS_PATTERN
        # userClient->member (make member symbolic)
        addr = state.solver.eval(state.inspect.mem_read_address)
        if state.solver.symbolic(state.inspect.mem_read_address):
            sym_cont = state.solver.BVS('tmp_%x' % addr, state.inspect.mem_read_length * 8)
            concrete_cont = state.solver.eval(cont)
            state.solver.add(sym_cont == concrete_cont)
            state.memory.store(state.inspect.mem_read_address, sym_cont, endness=state.arch.memory_endness, inspect=False)

            var = get_tmp_var(state.inspect.mem_read_address)
            # rep = get_repr(state.inspect.mem_read_address, state.globals["trace"])
            # base pointer, expr
            state.globals["trace"][addr] = (var, state.inspect.mem_read_address)
            # from IPython import embed; embed()
        else:  # global variables (0xffffff7f9822daa8)
            executor = state.globals["executor"]
            _, rel = executor.getBaseAddr(addr)  # Get offset to the binary
            if rel:
                sym_cont = state.solver.BVS('tmp_%x' % addr, state.inspect.mem_read_length * 8)
                concrete_cont = state.solver.eval(cont)
                state.solver.add(sym_cont == concrete_cont)
                state.memory.store(addr, sym_cont, endness=state.arch.memory_endness, inspect=False)
                # base pointer, expr
                state.globals["trace"][addr] = (rel, state.solver.BVV(rel, 64))
                # from IPython import embed; embed()
        # end if config.MEM_ACCESS_PATTERN
        return
    
    print("content:", cont)
    fields = set()
    extractFields(cont, fields)
    if len(fields) > 0:
        print("onSymbolicRead", hex(state.addr), fields)
        # Record all accessed memory
        variables = state.locals.get("variables", set())
        variables.update(fields)
        state.locals["variables"] = variables

def check_dependence(state, exprs, resc_name):
    symbols = defaultdict(list)
    if type(exprs) in [tuple, list]:
        for expr in exprs:
            extractSymbols(expr, symbols, excludes=["tmp_"])
    else:
        extractSymbols(exprs, symbols, excludes=["tmp_"])

    # typically only one dependence and no other variable
    if len(symbols) != 1:
        return None
    for sym, arr in symbols.items():
        if len(arr) != 1:
            return None

        r, l = arr[0]
        print(sym, r, l)
        data = state.globals.get("deps", dict())
        isNew = True
        if sym._encoded_name in data:
            for (right, left, resource) in data[sym._encoded_name]:
                # if right < r or left > l:
                #     raise Exception("dependence range is larger than expected %d %d" %(r, l))
                if right >= r and left <= l: # same position
                    if resource != resc_name:
                        from IPython import embed; embed()
                        raise Exception("Inconsistent dependence between %s and %s" % (resc_name, resource))
                    isNew = False
        else:
            data[sym._encoded_name] = list()
        if isNew:
            # For argument of pointer, we only access the first two bytes, thus we recover the size for it.
            connections = state.globals["connections"]
            size = connections[resc_name]
            if (r - l + 1) > size:
                raise Exception("Resource size %d is larger then expected %d" % (r-l+1, size))
            l = r - size + 1

            data[sym._encoded_name].append((r, l, resc_name))
            state.globals["deps"] = data
            print("Halt. Find a new dependence variable!")
            print(r, l, resc_name)
            state.locals["halt"] = True

def find_resource(deps, exprs):
    if len(deps) == 0:
        return None

    symbols = defaultdict(list)
    if type(exprs) in [list, set, tuple]:
        for expr in exprs:
            extractSymbols(expr, symbols, excludes=["tmp_"])
    else:
        extractSymbols(exprs, symbols, excludes=["tmp_"])

    # We only look at those checks/arguments involving one variable.
    if len(symbols) != 1:
        return None
    for sym, arr in symbols.items():
        if len(arr) != 1:
            return None
        right, left = arr[0]
        print(sym, right, left)
        if sym._encoded_name not in deps:
            return None

        for (r, l, resource) in deps[sym._encoded_name]:
            if r >= right and l <= left:
                return resource

    return None

def memAccess(state, expr):
    if expr.op != "__eq__":
        return False

    if expr.args[0].op == 'BVV' and state.solver.eval(expr.args[0]) > 0xffffff8000000000: # kernel object
        return True
    if expr.args[1].op == 'BVV' and state.solver.eval(expr.args[1]) > 0xffffff8000000000:
        return True

    return False

def onConstraint(state):
    """ Dependence inference by looking at checks
    """
    # Note: for block followed by switch jump, the address can be symbolic and thus cannot be accessed
    # by state.addr.
    addr = state.solver.eval(state.regs.rip)
    if addr > 0xffffff8000000000:
        return

    for each in state.inspect.added_constraints:
        if state.solver.eval(each) == False:
            return

    print("onConstraint", state.regs.rip, state.inspect.added_constraints)
    # ignore memory concretization
    # e.g., (<Bool Reverse(tmp_ffffff8008e69ba8_17_64) + 0xd0 == 0xffffff80085ab2d0>,)
    if state.inspect.added_constraints[0].op == '__eq__' and state.inspect.added_constraints[0].args[1].op == 'BVV':
        if state.solver.eval(state.inspect.added_constraints[0].args[1]) > 0xffffff8000000000:
            return

    # Check if we encounter a check involving dependence
    res = state.globals.get("resource", dict())
    if addr in res:
        if res[addr] is None:
            # No need to check
            return

        # There must be a dependence variable involved
        check_dependence(state, state.inspect.added_constraints, res[addr])
    else:
        # First time arrive here
        deps = state.globals.get("deps", dict())
        symbols = defaultdict(list)
        for expr in state.inspect.added_constraints:
            extractSymbols(expr, symbols, excludes=["tmp_", "RDTSC_"])
        if len(symbols) == 1:
            for sym, arr in symbols.items():
                if len(arr) != 1:
                    break

                right, left = arr[0]
                print(sym, right, left)
                
                found = False
                if sym._encoded_name in deps:
                    for (r, l, resource) in deps[sym._encoded_name]:
                        if r >= right and l <= left:
                            # Note unlike dependence derived from arguments, those involved in checks are more
                            # accurate and stable, therefore we store a None whenever we do not see dependence.
                            # Record the address, as well as the access parttern.
                            res[addr] = resource
                            # if config.MEM_ACCESS_PATTERN
                            for expr in state.inspect.added_constraints:
                                r = access_tree(expr, deps, state.globals["trace"], state.globals["trace_cache"])
                                print(str(r))
                                if r.qualify():
                                    state.globals["access_resource"][r] = resource
                                    # print("add access tree")
                                    # from IPython import embed; embed()
                            # end if # if config.MEM_ACCESS_PATTERN
                            found = True
                            break
                # if config.MEM_ACCESS_PATTERN
                if not found:
                    # no resource found
                    for expr in state.inspect.added_constraints:
                        p = access_tree(expr, deps, state.globals["trace"], state.globals["trace_cache"])
                        print(str(p))
                        if not p.qualify():
                            continue
                        # print("find access tree")

                        for tree, resource in state.globals["access_resource"].items():
                            if tree.match(p):
                                connections = state.globals["connections"]
                                size = connections[resource]
                                if (right - left + 1) > size:
                                    raise Exception("Resource size %d is larger then expected %d" % (right-left+1, size))
                                left = right - size + 1
                                if sym._encoded_name not in deps:
                                    deps[sym._encoded_name] = list()
                                deps[sym._encoded_name].append((right, left, resource))
                                state.globals["deps"] = deps
                                print("Halt. Find a new dependence variable!")
                                print(right, left, resource)
                                state.locals["halt"] = True
                                res[addr] = resource
                                break
                # end if # if config.MEM_ACCESS_PATTERN

        # Write back
        state.globals["resource"] = res

def check_arg_dependence(state, arg, deps, resc_name):
    resource = None
    value = arg.get_value(state)
    print("check_arg_dependence", hex(state.addr), value, resc_name)
    # if not arg.is_ptr: isPointer is not accurate, thus we abandon it!
    # If it is not a pointer, it is possible that our analysis went wrong and thus
    # we still check if it is a pointer later.
    if state.solver.symbolic(value):
        resource = find_resource(deps, [value])
        if resource:
            return resource

        if resc_name is not None:
            check_dependence(state, [value], resc_name)

    # Check if it is a pointer
    solutions = state.solver.eval_upto(value, 2)
    if len(solutions) == 1:
        ptr = solutions[0]
        # How about other stack/heap pointers?
        if 0xc0000000 <= ptr <= 0xd0000000: # special region for allocation
            cont = state.memory.load(ptr, 2, inspect=False)  # Assume dependence has at least 2 bytes
            if state.solver.symbolic(cont):
                print(cont)
                # FIXME: If we have two states that contain dependence, first one will halt 
                # but the other one will continue as we mark the dependence as known.
                resource = find_resource(deps, cont)
                if resource:
                    return resource

                if resc_name is not None:
                    check_dependence(state, [cont], resc_name)

    return resc_name

def onFunctionCall(state):
    """ Dependence inference by looking at functions' arguments
    """
    # print(hex(state.addr), state.inspect.function_address)
    functions = state.globals.get("functions", dict())
    if state.addr not in functions:
        # No calling convention for this function
        return

    # track all the functions we visited.
    # If one function is only visited by one particular state, 
    # that state can not be discarded.
    # TODO: what if one function is visited by two states and both states are discarded?
    if state.addr < 0xffffff8000000000:
        visited = state.locals.get("visited", set())
        visited.add(state.addr)
        state.locals["visited"] = visited

    res = state.globals.get("arg_resource", dict())
    deps = state.globals.get("deps", dict())

    if state.addr in res:
        # Note: dependence may have special value like 0 or -1.
        for i, arg in enumerate(functions[state.addr]):
            resource = check_arg_dependence(state, arg, deps, res[state.addr][i])
            if resource != res[state.addr][i] and res[state.addr][i] is not None:
                print("Addr: 0x%x, idx: %d" % (state.addr, i))
                raise Exception("Inconsistent dependence between %s and %s" % (res[state.addr][i], resource))
            res[state.addr][i] = resource
    else:
        # First time
        new_deps = []
        for i, arg in enumerate(functions[state.addr]):
            resource = check_arg_dependence(state, arg, deps, None)
            new_deps.append(resource)
        res[state.addr] = new_deps
        print("onFunctionCall", hex(state.addr), new_deps)

    # Write back
    state.globals["arg_resource"] = res

class InferenceExecutor(MacExecutor):
    def __init__(self, proxy, binary, kext, service, client, index, syscall, entry, isConcolic, timeout):
        MacExecutor.__init__(self, proxy, binary, kext, entry, isConcolic=isConcolic)

        self.service = service
        self.client = client
        self.index = index
        self.syscall = syscall
        self.timeout = timeout or 60*5

        self.model = loads(os.path.join(ModelPath, client.metaClass))
        self.dispatchtable = loads(os.path.join(ServicePath, client.metaClass))
        self.cmd = syscall.getCmdHandler(self.model.selector)

        self.states = dict()
        self.waypoint = set()
        self.dead = set()

        self.kernel_func_mapping = dict()

    def get_arguments_selector(self, state):
        if self.client.externalMethod:
            # externalMethod(this, uint32_t selector, IOExternalMethodArguments * args,
            #    IOExternalMethodDispatch * dispatch, OSObject * target, void * reference )
            args = state.regs.rdx
            selector = state.regs.esi

            # symbolize global variables
            uClient = state.regs.rdi
            # sym_client = state.solver.BVS("tmp_userclient", 64, key=('tmp_userclient', 8), eternal=True)
            sym_client = state.solver.BVS("tmp_00000000", 64)
            state.solver.add(sym_client == uClient)
            state.regs.rdi  = sym_client
            logger.debug(f"symbolize userClient {uClient}, {sym_client}")
            # TODO: collect all global variables
        elif self.client.getTargetAndMethodForIndex:
            # IOUserClient::getTargetAndMethodForIndex(IOService **targetP, UInt32 index)
            # FIXME: automatically detect the register that stores args
            args = state.regs.r12
            selector = state.regs.rdx
        else:
            raise Exception("no newUserClient")
        return args, selector

    def pre_execute_symbolize(self, state):
        args, selector = self.get_arguments_selector(state)

        # args = state.regs.rdx
        selector = state.solver.eval(selector)
        # asyncWakePort = state.solver.eval(state.memory.load(args+0x8, 8, inspect=False))  # args->asyncWakePort
        scalarInput = state.solver.eval(state.mem[args+0x20].uint64_t.resolved)  # args->scalarInput
        scalarInputCount = state.solver.eval(state.mem[args+0x28].uint32_t.resolved) # args->scalarInputCount
        structInput = state.solver.eval(state.mem[args+0x30].uint64_t.resolved)   # args->structureInput
        structInputSize = state.solver.eval(state.mem[args+0x38].uint32_t.resolved)   # args->structureInputSize
        scalarOutput = state.solver.eval(state.mem[args+0x48].uint64_t.resolved)  # args->scalarOutput
        scalarOutputCount = state.solver.eval(state.mem[args+0x50].uint32_t.resolved)  # args->scalarOutputCount
        structOutput = state.solver.eval(state.mem[args+0x58].uint64_t.resolved)  # args->structureOutput
        structOutputSize = state.solver.eval(state.mem[args+0x60].uint32_t.resolved)  # args->structureOutputSize
        print("selector", selector)
        print("scalarInput*", hex(scalarInput))
        print("scalarInputCount", scalarInputCount)
        print("structInput*", hex(structInput))
        print("structInputSize", structInputSize)
        print("scalarOutput*", hex(scalarOutput))
        print("scalarOutputCount", scalarOutputCount)
        print("structOutput", hex(structOutput))
        print("structOutputSize", structOutputSize)

        kernel = getConfigKey("kernel")
        # image lookup -t IOExternalMethodArguments
        inputCntOffset, inputStructCntOffset, outputCntOffset, outputStructCntOffset = [
            LLDBDebugger.fieldOffset(field, "IOExternalMethodArguments", kernel) 
            for field in [
                "scalarInputCount",
                "structureInputSize",
                "scalarOutputCount",
                "structureOutputSize"
            ]
        ]

        syscall = self.syscall
        # concretize args
        # No need to symbolize output buffer
        # selector is always constant.
        if syscall.selector.getData() != selector:
            print(syscall.selector, selector)
            raise Exception("Wrong selector")
        if syscall.inputCnt.type != "const":
            sym_inputCnt = state.solver.BVS("inputCnt", 32, key=('inputCnt', 4), eternal=True)
            state.memory.store(args+inputCntOffset, sym_inputCnt)
        if syscall.inputStructCnt.type != "const":
            sym_inputStructCnt = state.solver.BVS("inputStructCnt", 32, key=('inputStructCnt', 8), eternal=True)
            state.memory.store(args+inputStructCntOffset, sym_inputStructCnt)
            # add constraints to inputStructCnt, otherwise we may encounter OOB read/write as the length
            # of inputStruct is fixed.
            # FIXME: 1024 seems to be small in some cases.
            # state.solver.add(Reverse(sym_inputStructCnt) <= 1024)
        if syscall.outputCnt.type != "const":
            sym_outputCnt = state.solver.BVS("outputCnt", 32, key=('outputCnt', 4), eternal=True)
            state.memory.store(args+outputCntOffset, sym_outputCnt)
        if syscall.outputStructCnt.type != "const":
            sym_outputStructCnt = state.solver.BVS("outputStructCnt", 32, key=('outputStructCnt', 8), eternal=True)
            state.memory.store(args+outputStructCntOffset, sym_outputStructCnt)
            # state.solver.add(Reverse(sym_outputStructCnt) <= 1024)

        def concretize(ctx, typ):
            # input or inputStruct
            if ctx.dir&PtrType.DirIn == 0:
                return

            # concretize following types
            if typ.type in ("ptr", "resource", "const"):
                path = list(ctx.path)
                data = None
                while len(path) > 0:
                    path = path[:-1]
                    key = (ctx.arg, str(path))
                    if key in ctx.ret:
                        data = ctx.ret[key]
                        break
                if data is None:
                    return

                # concretize pointer, constant, and dependence
                print(data)
                print("concretize %s: %d %d" % (typ.type, typ.offset, typ.size))
                symbol = data["symbol"]
                sym = Extract(symbol.length-1-typ.offset*8, symbol.length-(typ.offset+typ.size)*8, symbol)
                # concrete = read_memory(state, data["addr"]+typ.offset, typ.size, task)
                concrete = state.memory.load(data["addr"]+typ.offset, typ.size)
                state.solver.add(sym == concrete)
                print(sym, concrete)

                if typ.type == "resource":
                    # store info of resource for fast check
                    data = state.globals.get("deps", dict())
                    if symbol._encoded_name not in data:
                        data[symbol._encoded_name] = list()
                    data[symbol._encoded_name].append((symbol.length-typ.offset*8-1, \
                        symbol.length-(typ.offset+typ.size)*8, typ.name))
                    state.globals["deps"] = data

                if typ.type == "ptr":
                    # create symbolic memory for pointee
                    p = state.solver.eval(Reverse(concrete))
                    if p != 0:
                        # concrete = state.memory.load(p, typ.ref.size)
                        # create and register pointer
                        sym_cont = state.solver.BVS("mem_%x" % p, typ.ref.size*8, key=("mem", p), eternal=True)
                        ctx.ret[(ctx.arg, str(ctx.path))] = {"addr": p, "symbol": sym_cont}
                        # if isConcolic:
                        #     # concretize the whole memory
                        #     state.solver.add(sym_cont == concrete)

        ctx = Context()
        ctx.ret = dict()
        if scalarInput and syscall.input.type == "ptr":
            sym_scalarInput = state.solver.BVS("input", syscall.input.ref.size*8, \
                key=("input", syscall.input.ref.size), eternal=True)
            ctx.ret[("input", str([2]))] = {"addr": scalarInput, "symbol": sym_scalarInput}
            # state.solver.register_variable(sym_scalarInput, ('mem', scalarInput), eternal=True)
        if structInput and syscall.inputStruct.type == "ptr":
            sym_structInput = state.solver.BVS("inputStruct", syscall.inputStruct.ref.size*8, \
                key=("inputStruct", syscall.inputStruct.ref.size), eternal=True)
            ctx.ret[("inputStruct", str([4]))] = {"addr": structInput, "symbol": sym_structInput}
            # state.solver.register_variable(sym_structInput, ('mem', structInput), eternal=True)
        syscall.visit(ctx, concretize)

        for _, data in ctx.ret.items():
            print(data)
            state.memory.store(data["addr"], data["symbol"])

    def setDeadEnd(self, state):
        if self.client.externalMethod:
            super(InferenceExecutor, self).setDeadEnd(state)
        elif self.client.getTargetAndMethodForIndex:
            # We want to continue to execute after this function is returned.
            # Set the dead end when starting executing our target function (see @execute).
            pass
        else:
            raise Exception("not implemented yet!")

    def pre_execute(self, state):
        # make inputs symbolic or concrete
        self.pre_execute_symbolize(state)

        # set breakpoints
        state.inspect.b('mem_read', when=angr.BP_BEFORE, action=onSymbolicRead)
        if options.infer_dependence:
            print("enable dependence inference")
            state.inspect.b('constraints', when=angr.BP_BEFORE, action=onConstraint)
            # CvvT: Should we also consider jmp?
            state.inspect.b('call', when=angr.BP_AFTER, action=onFunctionCall)

        basename = os.path.basename(self.filename)
        # functions should be loaded first as we need to get the addresses of kernel functions.
        state.globals["functions"] = self.load_functions(os.path.join("workdir", "cc", basename))
        state.globals["resource"] = self.load_resource(os.path.join(ResourcePath, self.client.metaClass, "resource.json"))
        state.globals["arg_resource"] = self.load_resource(os.path.join(ResourcePath, self.client.metaClass, "arg_resource.json"))
        state.globals["connections"] = self.load_connections()

        state.globals["trace"] = dict()
        state.globals["trace_cache"] = dict()
        state.globals["access_resource"] = loads(os.path.join(ResourcePath, self.client.metaClass, "access_resource"), dict())

    def post_execute(self, simgr):
        super(InferenceExecutor, self).post_execute(simgr)

        # TODO: figure out which states are desired
        if "waypoint" in simgr.stashes and len(simgr.waypoint) > 0:
            stash = "waypoint"
        else:
            stash = "dead"

        print("post_execute:")
        print(simgr)

        self.remove_error(simgr, stash)
        dep_states = simgr.halt if "halt" in simgr.stashes else []
        self.evaluate(simgr.stashes[stash] + dep_states, save=True)

        # from IPython import embed; embed()

        # For global info, we can provide any state.
        self.save_resource(simgr.stashes[stash][0], "resource", os.path.join(ResourcePath, self.client.metaClass, "resource.json"))
        self.save_resource(simgr.stashes[stash][0], "arg_resource", os.path.join(ResourcePath, self.client.metaClass, "arg_resource.json"))
        dumps(os.path.join(ResourcePath, self.client.metaClass, "access_resource"), simgr.stashes[stash][0].globals["access_resource"])
        return True

    def execute(self, simgr):
        start_time = time.time()
        method = self.dispatchtable.methods[self.cmd]
        tgt = 0
        if method.method.startswith("externalMethod_"):
            tgt = self.target_base + method.addr
        else:
            sym = find(self.proj, method.method, fuzzy=False)
            if len(sym) == 0:
                raise Exception("%s is not found" % method.method)
            tgt = self.target_base + sym[0].relative_addr
        print("target add is 0x%x" % tgt)

        steps = 0
        if tgt:
            # Eliminate error states
            while not self.should_abort:
                simgr.move(from_stash="active", to_stash="waypoint", filter_func=lambda s: s.addr == tgt)
                self.move(simgr, steps)
                # FIXME: for now we halt once we encounter dependence.
                if "halt" in simgr.stashes and len(simgr.halt) > 0:
                    simgr.move(from_stash="halt", to_stash="waypoint")
                    self.abort()
                    break

                if len(simgr.active) == 0:
                    break

                # print(simgr.active[0].regs.rip)
                for idx, each in enumerate(simgr.active):
                    print("state %d" % idx, hex(each.addr))
                    print("-------------------------------")

                simgr = simgr.step()
                steps += 1

            if self.should_abort:
                return simgr

            simgr.move(from_stash="waypoint", to_stash="active")
            if len(simgr.active) == 0:
                if options.infer_dependence:
                    raise TargetException("Failed to execute to the target address 0x%x" % method.addr)
                return simgr
            simgr._clear_states("deadended")

        if self.client.externalMethod == 0 and self.client.getTargetAndMethodForIndex:
            # Now that we encouter the target function, we could set the dead end.
            ret_addr = self.proj.simos.return_deadend
            if len(simgr.active) != 1:
                raise Exception("multiple states when executing the target function")
            state = simgr.active[0]
            print("reg rsp:", state.regs.rsp)
            print(state.mem[state.regs.rsp].uint64_t.resolved)
            state.memory.store(state.regs.rsp, state.solver.BVV(ret_addr, 64), endness=state.arch.memory_endness, inspect=False)

        print("reached target function")
        while not self.should_abort:
            self.move(simgr, steps)
            if "halt" in simgr.stashes and len(simgr.halt) > 0:
                # FIXME: for now we halt once we encounter dependence.
                simgr._clear_states("waypoint")
                simgr.move(from_stash="halt", to_stash="waypoint")
                self.abort()
                break
            if len(simgr.active) == 0:
                break

            # for each in simgr.active:
            #     if each.addr == 0x99620 + self.target_base:
            #         from IPython import embed; embed()
            #         pass

            print(simgr.active[0].regs.rip)
            simgr = simgr.step()
            steps += 1
            if time.time() - start_time > self.timeout or len(simgr.active) > 96:  # timeout
                print("timeout or too many states, stop!")
                self.abort()
                for each in simgr.active:
                    self.states[each] = steps
                simgr.move(from_stash="active", to_stash="waypoint")
                simgr.move(from_stash="dead", to_stash="waypoint")
                break

        return simgr

    def remove_error(self, simgr, stash):
        if len(simgr.stashes[stash]) <= 1:
            return

        points = [(each, self.states[each]) for each in simgr.stashes[stash]]
        print("total states:", points)
        
        # from IPython import embed; embed()

        root = clustering(points)
        root = prune(root)
        print("remaining states:", root.points)
        states = [state for state, v in root.points]
        simgr._clear_states(stash)
        simgr._store_states(stash, states)

    def evaluate(self, states, save=True):
        halt_syscalls, complete_syscalls = [], []
        syscall = self.syscall
        for state in states:
            fuzzy = state.locals.get("halt", False)
            call = syscall.copy()
            call.numOfBB = self.states[state]
            if fuzzy:
                if syscall.input.type == "ptr":
                    input_type = SymType("input", fuzzy=True)
                    input_type.initialize(state, state)
                    input_type.refineLen([2])
                    print("input: \n%s\n" % input_type.repr())
                    ip = Type.construct(input_type.toJson())
                    print(ip.repr())
                    call.input = call.input.refine(ip)
                if syscall.inputStruct.type == "ptr":
                    inputStruct_type = SymType("inputStruct", fuzzy=fuzzy)
                    inputStruct_type.initialize(state, state)
                    inputStruct_type.refineLen([4])
                    print("inputStruct: \n%s\n" % inputStruct_type.toJson())
                    ips = Type.construct(inputStruct_type.toJson())
                    print(ips.repr())
                    call.inputStruct = call.inputStruct.refine(ips)

                call.validate()
                halt_syscalls.append(call)
            else:
                if syscall.input.type == "ptr":
                    input_type = SymType("input", fuzzy=fuzzy)
                    input_type.initialize(state, state)
                    input_type.refineLen([2])
                    print("input: \n%s\n" % input_type.repr())
                    ip = Type.construct(input_type.toJson())
                    print(ip.repr())
                    call.input = ip
                if syscall.inputStruct.type == "ptr":
                    inputStruct_type = SymType("inputStruct", fuzzy=fuzzy)
                    inputStruct_type.initialize(state, state)
                    inputStruct_type.refineLen([4])
                    print("inputStruct: \n%s\n" % inputStruct_type.toJson())
                    ips = Type.construct(inputStruct_type.toJson())
                    print(ips.repr())
                    call.inputStruct = ips

                def refine_size(name):
                    v = list(state.solver.get_variables(name))
                    if len(v):
                        sym = v[0][1]
                        t = SymType(sym)
                        t.initialize(state, state)
                        ipc = Type.construct(t.toJson())
                        return ipc
                    return None

                def count_access(typ):
                    def func(ctx, t):
                        if t.type == "struct":
                            count = 0
                            for field in t.fields:
                                if field.access:
                                    count += field.size
                            ctx.ret = count
                            return True
                        elif t.type == "buffer":
                            if t.access:
                                ctx.ret = 8
                                return True

                    ctx = Context()
                    ctx.ret = 0
                    typ.visit(ctx, func)
                    return ctx.ret

                # FIXME: if counters were not accessed, we assume it is useless and thus becomes zero.
                if call.inputCnt.type != "const":
                    ret = refine_size("inputCnt")
                    if ret:
                        print("inputCnt")
                        print(ret.repr())
                        call.inputCnt = call.inputCnt.refine(ret)
                        if call.inputCnt.type == "buffer" and not call.inputCnt.access:
                            # assume inputCnt <= 1
                            c = (count_access(call.input)+7)//8
                            call.inputCnt = Constant(c, 4, None)
                if call.inputStructCnt.type != "const":
                    ret = refine_size("inputStructCnt")
                    if ret:
                        print("inputStructCnt")
                        print(ret.repr())
                        # FIXME: temporary fix
                        if ret.type == "const" and ret.getData() > 8192:
                            ret = call.inputStructCnt
                            ret.access = True

                        call.inputStructCnt = call.inputStructCnt.refine(ret)
                        if call.inputStructCnt.type == "buffer" and not call.inputStructCnt.access:
                            call.inputStructCnt = Constant(count_access(call.inputStruct), 4, None)
                # outputCnt and outputStructCnt are pointers
                if call.outputCnt.type == "ptr":
                    ret = refine_size("outputCnt")
                    if ret:
                        print("outputCnt")
                        print(ret.repr())
                        call.outputCnt.ref = call.outputCnt.ref.refine(ret)
                        # If there is no use of the outputCnt, we can assume that it is <= 1.
                        # In the case where outputCnt = 1, output is a null pointer?
                        if call.outputCnt.ref.type == "buffer" and not call.outputCnt.ref.access:
                            call.outputCnt.ref = Constant(1, 4, None)
                if call.outputStructCnt.type == "ptr":
                    ret = refine_size("outputStructCnt")
                    if ret:
                        print("outputStructCnt")
                        print(ret.repr())
                        call.outputStructCnt.ref = call.outputStructCnt.ref.refine(ret)
                        if call.outputStructCnt.ref.type == "buffer" and not call.outputStructCnt.ref.access:
                            # FIXME: default size for outputStruct
                            call.outputStructCnt.ref = Constant(0, 4, None)

                call.validate()
                refine_buffer(call)
                complete_syscalls.append(call)

        # Remove the original syscall and add back new syscalls
        if syscall.CallName == "syz_IOConnectCallMethod":
            del self.model.methods[self.cmd][self.index]
            halt_syscalls = reduce_syscalls(halt_syscalls + \
                [call for call in self.model.methods[self.cmd] if call.status == 0])
            complete_syscalls = reduce_syscalls(complete_syscalls + \
                [call for call in self.model.methods[self.cmd] if call.status])
        elif syscall.CallName == "syz_IOConnectCallAsyncMethod":
            del self.model.async_methods[self.cmd][self.index]
            halt_syscalls = reduce_syscalls(halt_syscalls + \
                [call for call in self.model.async_methods[self.cmd] if call.status == 0])
            complete_syscalls = reduce_syscalls(complete_syscalls + \
                [call for call in self.model.async_methods[self.cmd] if call.status])
        else:
            raise Exception("unknown syscall %s" % syscall.CallName)

        # from IPython import embed; embed()

        # Note: struct with fewer fields would be merged with larger struct and thus we 
        # reduce the length at last.
        for each in halt_syscalls:
            each.status = 0
            reduce_length(each)
        for each in complete_syscalls:
            each.status = 1
            reduce_length(each)
        # For complete syscalls we may have error paths left.
        # FIXME: is it necessary?
        # complete_syscalls = remove_error_syscall(complete_syscalls)

        new_syscalls = halt_syscalls + complete_syscalls
        # Reset syscall name
        for i, call in enumerate(new_syscalls):
            call.SubName = "%s_Group%d_%d" % (self.client.metaClass, self.cmd, i)
        
        if syscall.CallName == "syz_IOConnectCallMethod":
            self.model.methods[self.cmd] = new_syscalls
        elif syscall.CallName == "syz_IOConnectCallAsyncMethod":
            self.model.async_methods[self.cmd] = new_syscalls

        if save:
            dumps(os.path.join(ModelPath, self.client.metaClass), self.model)

    def move(self, simgr, step):
        """ Move states accordingly and record its steps.
        """
        if len(simgr.errored):
            self.abort()

        halt_states, dead_states, waypoint_states, remain = [], [], [], []
        for state in simgr.active:
            if state.locals.get("halt", False):
                halt_states.append(state)
                self.states[state] = step
            elif state.addr in self.dead:
                dead_states.append(state)
                self.states[state] = step
            elif state.addr in self.waypoint:
                waypoint_states.append(state)
                self.states[state] = step
            else:
                remain.append(state)

        for state in simgr.deadended:
            self.states[state] = step
        simgr.move(from_stash="deadended", to_stash="dead")

        for each in simgr.errored:
            if each.state not in self.states:
                self.states[each.state] = step

        if dead_states or waypoint_states or halt_states:
            simgr._clear_states("active")
            simgr._store_states("halt", halt_states)
            simgr._store_states("dead", dead_states)
            simgr._store_states("waypoint", waypoint_states)
            simgr._store_states("active", remain)

    def merge(self, simgr, stash):
        num_unique = 0
        while len(simgr.stashes[stash]) > 1:
            print(stash, len(simgr.stashes[stash]))
            num_unique += 1
            exemplar_callstack = simgr.stashes[stash][0].callstack
            simgr.move(stash, 'merge_tmp', lambda s: s.callstack == exemplar_callstack)
            print("...%d with unique callstack #%d" % (len(simgr.merge_tmp), num_unique))
            if len(simgr.merge_tmp) > 1:
                simgr = simgr.merge(stash='merge_tmp')
            simgr = simgr.move('merge_tmp', stash)

        return simgr

    # Utility
    def load_resource(self, path):
        data = dict()
        if os.path.exists(path):
            with open(path, "r") as f:
                for k, v in json.load(f).items():
                    if k in self.kernel_func_mapping:
                        data[self.kernel_func_mapping[k]] = v
                    else:
                        data[int(k) + self.target_base] = v
        return data

    def save_resource(self, state, key, path):
        data = {}
        extra = state.globals.get(key, dict())
        reverse_mapping = dict([(v, k) for k, v in self.kernel_func_mapping.items()])

        for ip, resource in extra.items():
            if ip in reverse_mapping:
                data[reverse_mapping[ip]] = resource
                print(reverse_mapping[ip], resource)
            else:
                _, addr = self.getBaseAddr(ip, target=self.target)
                if addr:
                    data[addr] = resource
                    print(hex(addr), resource)
            
        with open(path, "w") as f:
            json.dump(data, f)

    def load_functions(self, filepath):
        """ Get calling conventions for all functions
        """
        if not os.path.exists(filepath):
            raise Exception("calling convention does not exists: %s" % filepath)

        ret = dict()
        with open(filepath, "r") as fp:
            for k, v in json.load(fp).items():
                args = []
                for each in v:
                    args.append(Argument(each))
                # adjust the address for every function
                ret[self.target_base + int(k)] = args

        # Some speical kernel functions should also be considered
        kernel_func = {
            "OSArray::getObject": [
                Argument({"type": "SimRegArg", "reg_name": "rdi", "size": 8, "is_ptr": True}),
                Argument({"type": "SimRegArg", "reg_name": "esi", "size": 4, "is_ptr": False})
            ]
        }
        names = list(kernel_func.keys())
        funcs = self.proxy.find_functions_addr(names)
        for name, ents in funcs.items():
            for ent in ents:
                if not ent["inlined"]:
                    ret[ent["addr"]] = kernel_func[name]
                    self.kernel_func_mapping[name] = ent["addr"]
        # for i, addr in enumerate(addrs):
        #     ret[addr] = kernel_func[names[i]]
        #     self.kernel_func_mapping[names[i]] = addr
        return ret

    def load_connections(self):
        resources = dict()
        def search(ctx, typ):
            if typ.type == "resource":
                resources[typ.name] = typ.size * 8 # bit size

        # find all resources
        for _, syscalls in self.model.methods.items():
            for each in syscalls:
                ctx = Context()
                each.visit(ctx, search)

        print("resources:", resources)
        return resources

EXECUTE_NONE    = 0
EXECUTE_SUCCEED = 1
EXECUTE_FAIL    = 2

def rebuild_template(service, client, finalize=False):
    logger.debug("Re-generating template")
    model = loads(os.path.join(ModelPath, client.metaClass))
    outfile = generateTemplate(service.metaClass, client, model, finalize=finalize)
    build_template(outfile)

    testcases = os.path.join(TestCasePath, client.metaClass)
    if os.path.exists(testcases): # and not finalize:
        # Use the initial model
        model = loads(os.path.join(ModelPath, client.metaClass))
        outdir = generateTestcases(testcases, model, service.metaClass, client)
        subprocess.run(["bin/syz-json2syz", "-dir", outdir], check=True, cwd=getConfigKey("syzkaller"))


def any2int(num):
    if isinstance(num, str):
        if num.startswith("0x"):
            return int(num, 16)
    elif isinstance(num, list):
        return int.from_bytes(num, "little")
    elif isinstance(num, bytes):
        return int.from_bytes(num, "little")
    return num

def isTargetSyscall(proxy, client, syscall, _inputCnt, _inputStructCnt, _outputCnt, _outputStructCnt):
    logger.debug("checking syscall...")
    model = loads(os.path.join(ModelPath, client.metaClass))
    cmd = syscall.getCmdHandler(model.selector)

    if client.externalMethod:
        selector = model.selector
        args = any2int(proxy.read_register("rdx"))
        # Check whether the selector matches.
        if selector.op == "BVS" and selector._encoded_name.startswith(b'selector_'):
            val = any2int(proxy.read_register("rsi"))
            if val != cmd:
                logger.debug("cmd is %d, not %d" % (val, cmd))
                return False
        elif selector.op == "Extract" and selector.args[2].op == 'BVS':
            left = (selector.args[2].length-selector.args[0]-1)//8
            right = (selector.args[2].length-selector.args[1])//8
            target_selector = -1
            if selector.args[2]._encoded_name.startswith(b'structInput'):
                structInputP = any2int(proxy.read_memory(args+0x30, 8))
                if structInputP == 0: return False
                target_selector = any2int(proxy.read_memory(structInputP+left, right-left))
            else:
                raise Exception("unknown symbol %s" % selector.args[2]._encoded_name)
            if target_selector != cmd:
                logger.debug("cmd is %s, not %d" % (target_selector, cmd))
                return False
        else:
            raise Exception("Not implemented yet!")

        logger.debug("pass cmd check")
        # Check other fields with special values
        inputCnt = any2int(proxy.read_memory(args+0x28, 4))
        if _inputCnt != inputCnt:
            logger.debug("inputCnt is %d, not %d" % (inputCnt, _inputCnt))
            return False

        structInputCnt = any2int(proxy.read_memory(args+0x38, 4))
        if _inputStructCnt != structInputCnt:
            logger.debug("structInputCnt is %d, not %d" % (structInputCnt, _inputStructCnt))
            return False

        outputCnt = any2int(proxy.read_memory(args+0x50, 4))
        if _outputCnt != outputCnt:
            logger.debug("outputCnt is %d, not %d" % (outputCnt, _outputCnt))
            return False

        structOutputCnt = any2int(proxy.read_memory(args+0x60, 4))
        if _outputStructCnt != structOutputCnt:
            logger.debug("structOutputCnt is %d, not %d" % (structOutputCnt, _outputStructCnt))
            return False
    elif client.getTargetAndMethodForIndex:
        # TODO
        return True
    else:
        raise Exception("Not implemented yet!")
    return True

def execute(proxy, binary, kext, service, client, index, syscall, isConcolic, manual=False, timeout=0):
    syzkaller = getConfigKey("syzkaller")
    poc_path = os.path.join(syzkaller, "poc")
    if os.path.exists(poc_path):
        os.unlink(poc_path)

    logger.debug("analyzing syscall %s..." % syscall.Name)
    logger.debug("generating PoC...")
    validTestcase = os.path.join(PoCPath, "%s.syz" % syscall.SubName)
    if os.path.exists(validTestcase):
        buildPocFromSyz(validTestcase, poc_path)
        # TODO: do not hardcode it
        inputCnt, inputStructCnt, outputCnt, outputStructCnt = 16, 1024, 16, 1024
    else:
        cmds = ["%s/bin/syz-refine" % syzkaller, "-out", "poc", "-call", syscall.Name]
        if not isConcolic:  # allow constructing a testcase
            cmds.append("-gen")
        ret = subprocess.run(cmds, stderr=subprocess.PIPE, cwd=syzkaller)
        if not os.path.exists(poc_path):
            return EXECUTE_NONE

        # Give entitlement
        addEntitlement(poc_path)

        inputCnt, inputStructCnt, outputCnt, outputStructCnt = -1, -1, -1, -1
        for line in ret.stderr.split(b'\n'):
            line = line.decode("utf-8")
            if "inputCnt" in line:
                line = line[line.index("{"):]
                print(line)
                data = json.loads(line)
                inputCnt, inputStructCnt = data["inputCnt"], data["inputStructCnt"]
                outputCnt, outputStructCnt = data["outputCnt"], data["outputStructCnt"]
                break
        if inputCnt == -1:
            raise Exception("cannot get inputCnt")

    logger.debug("inputCnt: %d, inputStructCnt: %d, outputCnt: %d, outputStructCnt: %d" % 
        (inputCnt, inputStructCnt, outputCnt, outputStructCnt))

    # copy PoC to guest
    copy2vm(poc_path)
    logger.debug("copy PoC to guest")

    logger.info("binary: %s" % binary)
    logger.info("kext: %s" % kext)
    logger.info("externalMethod: 0x%x" % client.externalMethod)
    logger.info("getTargetAndMethodForIndex: 0x%x" % client.getTargetAndMethodForIndex)

    thr, lock = None, None
    try:
        remote_addr = getRemoteAddr()
        if not manual:
            subprocess.run(["ssh", remote_addr, "sudo dtrace -w -n \"BEGIN { breakpoint(); }\""])
            time.sleep(10)  # wait 10s to make it into effect
            logger.debug("suspend VM")

            # launch the debugger to connect kernel and our server.
            thr, lock = run_debugger(getConfigKey("kernel"))

        with proxy:
            entry = 0
            if client.externalMethod:
                entry = client.externalMethod
                logger.debug("set breakpoint for %s at 0x%x" % (kext, client.externalMethod))
            elif client.getTargetAndMethodForIndex:
                entry = client.getTargetAndMethodForIndex
                logger.debug("set breakpoint for %s at 0x%x" % (kext, client.getTargetAndMethodForIndex))
            else:
                raise Exception("Not implemented yet!")

            if not manual:
                # set breakpoint
                proxy.set_breakpoint(kext, entry)

                # make sure the vm is not stuck
                proxy.clear()

                # run PoC
                if client.access:
                    subprocess.run(["ssh", remote_addr, "~/poc"])
                else:
                    subprocess.run(["ssh", remote_addr, "sudo ~/poc"])
                logger.debug("execute the PoC in guest")

            # Set the task so that accessing userspace memory becomes feasible.
            proxy.set_task("poc")

            if not manual:
                # run until we reach the target
                while True:
                    proxy.wait_breakpoint()
                    if isTargetSyscall(proxy, client, syscall, inputCnt, inputStructCnt, outputCnt, outputStructCnt):
                        break
                    proxy.continue_run()

                # Remove all breakpoints (recover from int3)
                proxy.remove_breakpoints()

            executor = InferenceExecutor(proxy, binary, kext, service, client, index, syscall, \
                entry, isConcolic, timeout)
            # Sometimes it is difficult to model every possible function in the kernel that is
            # essential for the execution. Thereby, we provide a method to manually configure
            # some waypoints and dead points.
            for driver, addrs in getConfigKey("dead", default={}).items():
                for addr in addrs:
                    real_addr = executor.getTargetAddr(addr, driver)
                    print("dead point:", driver, hex(addr), real_addr)
                    if real_addr:
                        executor.dead.add(real_addr)
            for driver, addrs in getConfigKey("waypoint", default={}).items():
                for addr in addrs:
                    real_addr = executor.getTargetAddr(addr, driver)
                    print("waypoint:", driver, hex(addr), real_addr)
                    if real_addr:
                        executor.waypoint.add(real_addr)
            executor.run()
    finally:
        # reset the VM and lldb
        if lock:
            logger.debug("terminate lldb")
            lock.release()
            thr.join()

    vmrun("reset")
    time.sleep(60)

    # clean
    os.unlink(poc_path)
    return EXECUTE_SUCCEED

def analyze(proxy, binary, kext, service, client, index, syscall, isConcolic, update, manual=False, timeout=0):
    if update:
        rebuild_template(service, client)

    try:
        return execute(proxy, binary, kext, service, client, index, syscall, isConcolic, manual=manual, timeout=timeout)
    except (ProxyException, TIMEOUT):
        logger.error("proxy error occurs!")
        vmrun("reset")
        time.sleep(60)
    # except TargetException as e2:
    #     print(e2)
    #     vmrun("reset")
    #     time.sleep(60)
    #     return EXECUTE_NONE

    print("retrying...")
    return EXECUTE_FAIL

def has_resouce(model):
    resources = dict()
    def search(ctx, typ):
        if typ.type == "resource" and not typ.name.endswith("_port"):
            resources[typ.name] = True
            return True

    for _, syscalls in model.methods.items():
        for syscall in syscalls:
            syscall.visit(Context(), search)
    for _, syscalls in model.async_methods.items():
        for syscall in syscalls:
            syscall.visit(Context(), search)
    return len(resources) > 0

def type_inference(binary, kext, service, client, debugger=None, manual=False, timeout=0, targetCmd=None):
    # rebuild_.template(service, client)

    modelpath = os.path.join(ModelPath, client.metaClass)
    if not os.path.exists(modelpath):
        raise Exception("Please generate the default model with command argument --gen_template first")
    model = loads(modelpath)
    if not has_resouce(model):
        options.infer_dependence = False

    # Generate testcases before we proceed if we have any.
    testcases = os.path.join(TestCasePath, client.metaClass)
    if os.path.exists(testcases):
        logger.debug("Generating testcases")
        outdir = generateTestcases(testcases, model, service.metaClass, client)
        subprocess.run(["bin/syz-json2syz", "-dir", outdir], check=True, cwd=getConfigKey("syzkaller"))
    resourcedir = os.path.join(ResourcePath, client.metaClass)
    if not os.path.exists(resourcedir):
        os.mkdir(resourcedir)

    proxy = debugger if debugger else LLDBProxy()
    try:
        update = True
        keys = sorted(list(model.methods.keys()))
        for isConcolic in [True, False]:
            print("infer mode:", isConcolic)
            for cmd in keys:
                print("analyzing cmd %d" % cmd)

                if targetCmd is not None and cmd != targetCmd:
                    continue

                done = False
                while not done:
                    done = True
                    # Note model will be adjusted along the course, reload it to get the lastest one.
                    model = loads(modelpath)
                    for i, syscall in enumerate(model.methods[cmd]):
                        if syscall.status != 0:
                            continue

                        ret = analyze(proxy, binary, kext, service, client, i, syscall, isConcolic, update, manual=manual, timeout=timeout)
                        update = False if ret == EXECUTE_NONE else True
                        done = False if ret != EXECUTE_NONE else True

                done = False
                while not done:
                    done = True
                    model = loads(modelpath)
                    for i, syscall in enumerate(model.async_methods[cmd]):
                        if syscall.status != 0:
                            continue

                        ret = analyze(proxy, binary, kext, service, client, i, syscall, isConcolic, update, manual=manual, timeout=timeout)
                        update = False if ret == EXECUTE_NONE else True
                        done = False if ret != EXECUTE_NONE else True

        if targetCmd is not None:
            return

        done = True
        model = loads(modelpath)
        for cmd in keys:
            for each in model.methods[cmd]:
                if each.status == 0:
                    done = False
                    break
            for each in model.async_methods[cmd]:
                if each.status == 0:
                    done = False
                    break
            if not done:
                break

        # if methods and async methods differ a lot, we should only reserve one.
        if done:
            model = loads(modelpath)
            for cmd in keys:
                if len(model.methods[cmd]) and len(model.async_methods[cmd]):
                    cmax1 = max([each.numOfBB for each in model.methods[cmd]])
                    cmax2 = max([each.numOfBB for each in model.async_methods[cmd]])
                    # Same rule to eliminate error path
                    if cmax1 < cmax2/2 and cmax1 < 1000:
                        logger.debug("eliminate sync method %d (%d, %d)" % (cmd, cmax1, cmax2))
                        model.methods[cmd] = []
                    elif cmax2 < cmax1/2 and cmax2 < 1000:
                        logger.debug("eliminate async method %d (%d, %d)" % (cmd, cmax1, cmax2))
                        model.async_methods[cmd] = []
                # if sync call and async call have identical BBs, we only preserve one.
                if len(model.methods[cmd]) == len(model.async_methods[cmd]):
                    BBs = [each.numOfBB for each in model.methods[cmd]]
                    for syscall in model.async_methods[cmd]:
                        if syscall.numOfBB in BBs:
                            BBs.remove(syscall.numOfBB)
                    if len(BBs) == 0:
                        logger.debug("eliminate async method %d" % cmd)
                        model.async_methods[cmd] = []
            dumps(modelpath, model)
            # setup the proper environment for fuzzing
            rebuild_template(service, client, finalize=True)

        generateConfig(client)
        addEntitlement(os.path.join(getConfigKey("syzkaller"), "bin", "darwin_amd64", "syz-executor"))
    # except Exception as e:
    #     print(e)
    #     traceback.print_exc()
    #     raise Expce
    finally:
        logger.debug("exiting...")
        if debugger is None:
            proxy.exit()
