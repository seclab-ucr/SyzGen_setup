
import logging

import angr

from . import BaseModel, DummyModel, brkAlloc, Memset
from ..utils import get_sym_var

logger = logging.getLogger(__name__)

class KmallocTrackCaller(angr.SimProcedure):
    def run(self, size, flag, caller):
        logger.debug("Call __kmalloc_track_caller %s", size)
        return brkAlloc(self.state, size)

class Vmalloc(angr.SimProcedure):
    def run(self, size, flag):
        logger.debug("Call __vmalloc %s", size)
        return brkAlloc(self.state, size)

class AllocPerCPU(angr.SimProcedure):
    def run(self, size, align):
        logger.debug("Call __alloc_percpu %s", size)
        return brkAlloc(self.state, size)

class KmemCacheAllocTrace(angr.SimProcedure):
    def run(self, cache, flags, size):
        # void *kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags, size_t size)
        logger.debug("Call kmem_cache_alloc_trace %s", size)
        return brkAlloc(self.state, size)

class KmemCacheAlloc(angr.SimProcedure):
    def run(self, cache, flags):
        # kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)
        if self.state.solver.symbolic(cache):
            logger.debug("symbolic cache %s", cache)
            addr = get_sym_var(cache.ast, "glb")
            if addr is None:
                raise Exception("unknown cache")
        else:
            addr = self.state.solver.eval(cache)

        logger.debug("Call kmem_cache_alloc with cache 0x%x", addr)
        size = self.state.globals["cache"][addr]
        return brkAlloc(self.state, size)

class KmallocNode(angr.SimProcedure):
    def run(self, size, flags, node):
        # void *kvmalloc_node(size_t size, gfp_t flags, int node)
        logger.debug("Call kvmalloc_node %s", size)
        return brkAlloc(self.state, size)

class CopyFromUser(angr.SimProcedure):
    '''_copy_from_user(void *to, const void __user *from, unsigned long n)
    '''
    def run(self, to, addr, size):
        logger.debug("Call _copy_from_user %s %s %s", to, addr, size)
        cont = self.state.memory.load(addr, size, inspect=False)
        self.state.memory.store(to, cont, inspect=False)
        return 0

class LinuxModel(BaseModel):
    def __init__(self):
        pass

    def getFunc2Model(self):
        retWithZero = DummyModel()
        retWithOne = DummyModel(ret_value=1)
        procedures = {
            "mutex_lock": retWithZero,
            "mutex_unlock": retWithZero,
            "_raw_spin_lock_bh": retWithZero,
            "_raw_spin_unlock_bh": retWithZero,
            "_raw_spin_lock": retWithZero,
            "up_read": retWithZero,    # release a read lock
            "up_write": retWithZero,    # release a write lock
            "printk": retWithZero,
            "vprintk": retWithZero,
            "snprintf": retWithZero,
            "down_read": retWithZero,
            "_raw_spin_lock_irqsave": retWithZero,
            "rcu_barrier": retWithZero,
            "dump_stack": retWithZero,

            "__kmalloc_track_caller": KmallocTrackCaller(),
            "kfree": retWithZero,
            "__vmalloc": Vmalloc(),
            "vfree": retWithZero,
            "__alloc_percpu": AllocPerCPU(),
            "free_percpu": retWithZero,
            "kmem_cache_alloc_trace": KmemCacheAllocTrace(),
            "kvmalloc_node": KmallocNode(),
            "kfree_skb": retWithZero,
            "kmem_cache_alloc": KmemCacheAlloc(),

            "memset": Memset(),
            "_copy_from_user": CopyFromUser(),

            "queue_work_on": retWithOne,
        }

        return procedures

