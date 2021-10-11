
import logging
import angr

from angr.exploration_techniques import DFS

from ..models import ALIGN
from ..models.linux import LinuxModel
from ..executor.executor import BaseExecutor
from ..utils import access_tree

logger = logging.getLogger(__name__)

MAX_OBJECT = 4096 
STACK_BASE = 0xb0002000
GS_SIZE    = 0x20000
GS_BASE    = 0xb0003000
ALLOC_BASE = 0xb0003000 + GS_SIZE

def alloc_sym_mem(state, size=MAX_OBJECT, name=None, prefix='mem', init=True):
    global ALLOC_BASE
    addr = ALLOC_BASE
    ALLOC_BASE += ALIGN(size, 0x100)

    sym = None
    if init:
        if name:
            sym = state.solver.BVS(name, size*8, key=(name, size), eternal=True)
        else:
            sym = state.solver.BVS('%s_%x' % (prefix, addr), size*8)
        state.memory.store(addr, sym, inspect=False)

    return addr, sym

def onInstructionUD2(state):
    logger.debug("Executing ud2, killing...")
    state.regs.ip = state.project.simos.return_deadend

def onTranslateInstruction(state):
    b = state.project.factory.block(state.inspect.instruction)
    if b.capstone.insns:
        if b.capstone.insns[0].mnemonic == 'ud2':
            logger.debug("Hook ud2 at 0x%x", state.inspect.instruction)
            state.project.hook(state.inspect.instruction, onInstructionUD2, length=2)

def onMemoryWrite(state):
    addr = state.inspect.mem_write_address
    logger.debug("on Memory Write, %s, %s, 0x%x", addr, state.inspect.mem_write_expr, state.addr)


def onMemoryRead(state):
    addr = state.inspect.mem_read_address
    logger.debug("on Memory Read, %s, %s, 0x%x", addr, state.inspect.mem_read_length, state.addr)
    # cont = state.memory.load(addr, state.inspect.mem_read_length, \
    #         endness=state.arch.memory_endness, disable_actions=True, inspect=False)

    if state.solver.symbolic(addr):
        solutions = state.solver.eval_upto(addr, 2)
        rep = addr.__repr__(inner=True)
        ptr = None
        if len(solutions) > 1:
            # Find out if we have assigned a pointer before
            for k, v in state.solver.get_variables('ptr', rep):
                p = state.solver.eval(v)
                if k[1] == rep:
                    ptr = p
                    break

            if ptr is None:
                # If we didn't concretize this to a concrete pointer, assign one here.
                ptr, _ = alloc_sym_mem(state)

            logger.debug("%s == 0x%x" % (rep, ptr))
            ptr_bv = state.solver.BVV(ptr, 64)
            state.solver.add(addr == ptr_bv)
            # register this pointer to make sure the assignment is consistent across all states
            state.solver.register_variable(ptr_bv, ('ptr', rep), eternal=True)
        else:
            logger.debug("0x%x" % solutions[0])
            # from IPython import embed; embed()
    else:
        addr = state.solver.eval(addr)
        name = None
        if GS_BASE <= addr < GS_BASE+GS_SIZE:    # gs
            name = 'gs_%x' % addr
        elif addr >= 0xffffffff80000000:    # global variable
            sym = state.project.loader.find_symbol(addr)
            if sym:
                section = state.project.loader.main_object.sections[sym.section]
                if section.name in [".data", ".rodata"]:
                    # Having concrete data
                    return
            name = 'glb_%x' % addr
            
        if name is not None:
            sym_cont = state.solver.BVS(name, state.inspect.mem_read_length*8, key=(name,), eternal=True)
            state.memory.store(addr, sym_cont, endness=state.arch.memory_endness, inspect=False)
            logger.debug("initialize global memory %s", name)


class IOCTLExecutor(BaseExecutor):
    def __init__(self, binary, entry, cmd):
        super(IOCTLExecutor, self).__init__(binary, model=LinuxModel())

        self.entry = entry
        self.cmd = cmd

    def getInitState(self):
        state = self.proj.factory.blank_state(addr=self.entry)

        # set return address and stack
        deadend = self.proj.simos.return_deadend
        rsp = STACK_BASE   # 8k for stack
        state.regs.rsp = rsp
        state.memory.store(rsp, state.solver.BVV(deadend, 64), endness=state.arch.memory_endness, inspect=False)
        for i in range(1, 0x2001):    # init stack
            state.memory.store(rsp-i, state.solver.BVV(0, 8), inspect=False)

        # setup gs
        # current
        # mov    %gs:0x16d00,%rax
        state.regs.gs = GS_BASE

        # setup arguments
        file_addr, _ = alloc_sym_mem(state, name='file')
        state.regs.rdi = file_addr

        state.regs.esi = self.cmd

        addr, _ = alloc_sym_mem(state, name='arg')
        state.regs.rdx = addr

        state.inspect.b('mem_read', when=angr.BP_BEFORE, action=onMemoryRead)
        state.inspect.b('mem_write', when=angr.BP_BEFORE, action=onMemoryWrite)
        state.inspect.b('instruction', when=angr.BP_BEFORE, action=onTranslateInstruction)

        return state

    def load_cache(self, state):
        cache = dict()
        maps = {
            "radix_tree_node_cachep": 576,
        }
        for name, size in maps.items():
            sym = self.proj.loader.find_symbol(name)
            if sym is None:
                raise Exception("unknown cache")
            cache[sym.rebased_addr] = size
            logger.debug("load cache %s 0x%x: %d", name, sym.rebased_addr, size)

        state.globals["cache"] = cache

    def pre_execute(self, state):
        state.globals["trace"] = dict()
        state.globals["trace_cache"] = dict()

        state.globals["deps"] = dict()

        self.load_cache(state)

    def post_execute(self, simgr):
        return simgr

    def execute(self, simgr):
        exits = {
            0xffffffff81919450    # netdev_run_todo
        }
        simgr.use_technique(DFS())

        while not self.should_abort:
            if len(simgr.active) == 0:
                self.abort()
                break

            state = simgr.active[0]
            logger.debug("execute 0x%x (%d)", simgr.active[0].addr, len(simgr.deferred))
            if state.addr == 0xffffffff817b8272:
                logger.debug("n is %s", state.regs.eax)
            elif state.addr == 0xffffffff8143f280:
                logger.debug("input n is %s", state.regs.rdi)

            simgr.move(from_stash="active", to_stash="deadend", filter_func=lambda s: s.addr in exits)

            simgr = simgr.step()

# 0xffffffff81444b27: write ppp to slot
def TestIOCTLExecutorMain():
    binary = "/home/wchen130/workplace/SyzGen_setup/linux/vmlinux"
    executor = IOCTLExecutor(binary, 0xffffffff817baa10, 0xc004743e)
    executor.run()

