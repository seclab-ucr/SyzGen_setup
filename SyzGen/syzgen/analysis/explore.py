
import time
import logging

from ..config import Options

logger = logging.getLogger(__name__)
options = Options()

class TargetException(Exception):
    pass

class BaseExplorer:
    def __init__(self):
        self.states = dict()

        self.should_abort = False

    def abort(self):
        self.should_abort = True

    def pre_explore(self, simgr):
        return simgr

    def explore(self, simgr):
        return simgr

    def post_explore(self, simgr):
        return simgr

    def start_explore(self, simgr):
        simgr = self.pre_explore(simgr)
        simgr = self.explore(simgr)
        return self.post_explore(simgr)

class InterfaceExplorer(BaseExplorer):
    def __init__(self, target=0, waypoints=None, deads=None):
        super(InterfaceExplorer, self).__init__()

        self.target = target # the function we want to reach
        self.waypoint = set() if waypoints is None else waypoints    # waypoints we want to reach
        self.dead = set() if deads is None else deads    # waypoints where we want to terminate
        
        self.start_time = None
        self.steps = 0

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

    def pre_explore(self, simgr):
        if self.target:
            # Eliminate states that cannot reach target function
            while not self.should_abort:
                simgr.move(from_stash="active", to_stash="waypoint", filter_func=lambda s: s.addr == tgt)
                self.move(simgr, self.steps)

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
                self.steps += 1

            if self.should_abort:
                return simgr

            simgr.move(from_stash="waypoint", to_stash="active")
            if len(simgr.active) == 0:
                if options.infer_dependence:
                    raise TargetException("Failed to execute to the target address 0x%x" % method.addr)
                return simgr
            simgr._clear_states("deadended")

        return simgr

    def explore(self, simgr):
        while not self.should_abort:
            self.move(simgr, self.steps)
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
            self.steps += 1
            if time.time() - self.start_time > self.timeout or len(simgr.active) > 96:  # timeout
                print("timeout or too many states, stop!")
                self.abort()
                for each in simgr.active:
                    self.states[each] = self.steps
                simgr.move(from_stash="active", to_stash="waypoint")
                simgr.move(from_stash="dead", to_stash="waypoint")
                break

        return simgr

