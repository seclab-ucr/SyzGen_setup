
from syzgen.executor.executor import Executor

class SymExecutor(Executor):
    """
    Our main engine for dependence inference and structure recovery.
    """

    def __init__(self, proxy, binary, isConcolic, target, entry):
        """
        proxy: communicate with debugger
        binary: file path to the binary
        isConcolic: perform symbolic or concolic execution
        target: target kext name
        entry: {"externalMethiod", "dispatchMethod"}
        """
        super(SymExecutor, self).__init__(proxy, binary, isConcolic, target)

        self.entry = entry

    def getInitState(self):
        state = super(SymExecutor, self).getInitState()
        if self.isConcolic:
            # separate newly-added constraints from pre-assigned constraints
            blank_state = proj.factory.blank_state()
            state.globals['state'] = blank_state

        # load calling convention for each function
        state.globals["functions"] = load_functions(proj, BASE_ADDR)
        return state

    def symbolize(self, state):
        pass

    def concretize_cmd(self, state):
        pass
        
    def pre_execute(self, state):
        # FIXME: how to find these in a more general way?
        RET_EXTERNALMETHOD = self.target_base + 0x10cb6  # return from externalMethod
        SEND_REQUEST_FORMAT_ADDR = self.target_base + 0x56278
        LOG_PACKET_ADDR = self.target_base + 0x57d8

        CALL_GETINFO = self.target_base + 0x5f223
        CALL_SETIDLETIMERVALUE = self.target_base + 0x5b4e7

        HARDWARE_RESET_TEST = self.target_base + 0x1a19a
        TEST_ADVERTISE = self.target_base + 0x5fe45

        self.proj.hook(LOG_PACKET_ADDR, DummyStub())
        self.symbolize(state)
        if not self.isConcolic:
            self.concretize_cmd(cmd, state)

