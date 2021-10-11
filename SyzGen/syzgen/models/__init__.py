
import inspect
import logging
import angr

from claripy.ast.bv import Extract

logger = logging.getLogger(__name__)

MAX_MEMORY_SIZE = 1024
HEAP_LOCATION = 0xc0000000

ALIGN = lambda x, align: ((x+align-1)&(~(align-1)))
def brkAlloc(state, length):
    ptr = None

    def malloc(s, size):
        global HEAP_LOCATION

        addr = HEAP_LOCATION
        HEAP_LOCATION = ALIGN(HEAP_LOCATION+size, 8)

        print("heap_location: 0x%x, ptr: 0x%x, size: %d" % (HEAP_LOCATION, addr, size))
        return addr

    if state.solver.symbolic(length):
        size = state.solver.max_int(length)
        if size > MAX_MEMORY_SIZE: size = MAX_MEMORY_SIZE
        print("concretize Malloc size", length, size)
        ptr = malloc(state, size)
    else:
        size = state.solver.eval(length)
        if size > 8192:
            from IPython import embed; embed()
            raise Exception("brkAlloc size %d" % size)
        ptr = malloc(state, size)

    logger.debug("return ptr: 0x%x", ptr)

    for i in range(size):
        state.memory.store(ptr+i, state.solver.BVV(0, 8), inspect=False)
    return ptr 

class Memset(angr.SimProcedure):
    def run(self, dst, char, length):
        if self.state.solver.symbolic(length):
            size = self.state.solver.max_int(length)
            if size > MAX_MEMORY_SIZE: size = MAX_MEMORY_SIZE
        else:
            size = self.state.solver.eval(length)
        ptr = self.state.solver.eval(dst)
        c = Extract(7, 0, char.to_claripy())
        print("memset", ptr, c, size)
        for i in range(size):
            self.state.memory.store(ptr+i, c, inspect=False)

class DummyModel(angr.SimProcedure):
    def run(self, ret_value=0):
        if ret_value is not None:
            return ret_value

def dummyHook(state):
    pass

class BaseModel:
    def __init__(self):
        pass

    def getFunc2Model(self):
        return dict()

    def getFunc2Hook(self):
        return dict()

