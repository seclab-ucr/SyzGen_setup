
import logging
import angr

from angr.exploration_techniques import DFS
from angr.concretization_strategies import SimConcretizationStrategySolutions, SimConcretizationStrategyEval, SimConcretizationStrategyAny, SimConcretizationStrategyRange

from .explore import InterfaceExplorer

from ..executor.executor import LinuxExecutor, BaseExecutor
from ..debugger.gdbproxy import GDBProxy
from ..models.linux import LinuxModel

logger = logging.getLogger(__name__)

class TestLinuxExecutor(LinuxExecutor, InterfaceExplorer):
    def __init__(self, proxy, binary, entry):
        LinuxExecutor.__init__(self, proxy, binary, entry=entry)
        InterfaceExplorer.__init__(self)

    def execute(self, simgr):
        simgr = self.start_explore(simgr)

        # from IPython import embed; embed()

        return simgr

    def pre_execute(self, state):
        # ioctl(struct file *filp, unsigned int cmd_in, unsigned long arg)
        pass

def onConcretization(state):
    logger.debug("Concretization....")
    logger.debug("%s" % state.inspect.address_concretization_result)
    logger.debug("add constraint %s" % state.inspect.address_concretization_add_constraints)

class TestLinuxStaticExecutor(BaseExecutor):
    def __init__(self, binary, entry):
        super(TestLinuxStaticExecutor, self).__init__(binary, model=LinuxModel())

        self.entry = entry

    def getInitState(self):
        state = self.proj.factory.blank_state(addr=self.entry)

        # TODO: allocate unused memory region
        state.memory.write_strategies = [
            SimConcretizationStrategySolutions(8),
            SimConcretizationStrategyRange(64),
            SimConcretizationStrategyEval(1)
        ]
        # state.memory.read_strategies = [
        #     SimConcretizationStrategySolutions(8),
        #     SimConcretizationStrategyRange(64),
        #     SimConcretizationStrategyAny()
        # ]

        state.inspect.b('address_concretization', angr.BP_AFTER, action=onConcretization)

        sym_cmd = state.solver.BVS("cmd", 32, key=("cmd", 4), eternal=True)
        sym_arg = state.solver.BVS("arg", 1024*8, key=('arg', 1024), eternal=True)

        addr = 0xb0000000
        state.memory.store(addr, sym_arg, inspect=False)
        state.regs.esi = sym_cmd
        state.regs.rdx = addr

        # struct file
        file_addr = 0xb0020000
        state.regs.rdi = file_addr

        # set dead end
        deadend = self.proj.simos.return_deadend
        rsp = 0xb0010000
        state.regs.rsp = rsp
        state.memory.store(rsp, state.solver.BVV(deadend, 64), endness=state.arch.memory_endness, inspect=False)
        for i in range(1, 4096):  # init stack
            state.memory.store(rsp-i, state.solver.BVV(0, 8), inspect=False)

        return state

    def pre_execute(self, state):
        pass

    def post_execute(self, simgr):
        return simgr

    def execute(self, simgr):
        simgr.use_technique(DFS())
        # from IPython import embed; embed()

        sym_cmd = simgr.active[0].solver.get_variables("cmd")
        sym_cmd = list(sym_cmd)[0][1]

        cmds = []
        candidates = dict()
        while not self.should_abort:
            if len(simgr.active) == 0:
                self.abort()
                break

            cur = simgr.active[0]
            if cur.addr == 0xffffffff817bb050:
                logger.debug("Testing... %s", cur.regs.rbx)
                solns = cur.solver.eval_upto(cur.regs.rbx, 4)
                logger.debug("solutions %s" % solns)

            logger.debug("execute 0x%x (%d)" % (simgr.active[0].addr, len(simgr.deferred)))
            vmin = cur.solver.min(sym_cmd)
            vmax = cur.solver.max(sym_cmd)
            if vmin == vmax:
                logger.debug("Found a cmd %d" % vmin)
                cmds.append((vmin, cur.addr))
                simgr.move("active", "deadended")
            elif vmax - vmin <= 8:
                # multiple cases coalesced
                candidates[(vmin, vmax)] = cur.addr
                logger.debug("Possible cmds 0x%x-0x%x" % (vmin, vmax))
                
            simgr = simgr.step()

        for k, addr in candidates.items():
            found = False
            for cmd, _ in cmds:
                if k[0] <= cmd <= k[1]:
                    found = True
                    break
            if not found:
                logger.debug("add cmd 0x%x - 0x%x", k[0], k[1])
                for i in range(k[0], k[1]+1):
                    cmds.append((i, addr))

        for cmd, addr in cmds:
            print("0x%x --> 0x%x" % (cmd, addr))

        return simgr

def TestLinuxExecutorMain():
    binary = "/home/wchen130/workplace/SyzGen_setup/linux/vmlinux"
    # proxy = GDBProxy()
    try:
        # with proxy:
        executor = TestLinuxStaticExecutor(binary, 0xffffffff817baa10)
        executor.run()
    finally:
        pass
        # proxy.exit()

