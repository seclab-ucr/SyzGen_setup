
import logging
import pickle
import os
import subprocess
import angr
import time

from claripy.ast.bv import Reverse, Extract

from ..executor.executor import Executor, MacExecutor
from ..debugger.lldbproxy import LLDBProxy, setup_debugger
from ..debugger.proxy import ProxyException
from ..kext.macho import UserClient, check_effect_client, check_effect_service, check_service_property
from ..kext.helper import parse_signature, iterate_kext
from ..utils import demangle, dumps, loads, vmrun, getRemoteAddr
from ..config import ServicePath
from .static import parse_client

logger = logging.getLogger(__name__)

class NewUserClient(angr.SimProcedure):
    NO_RET = True
    
    def run(self, instance, gMetaClass, executor=None):
        metaClass = self.state.solver.eval(gMetaClass)
        driver, addr = executor.getBaseAddr(metaClass)
        print(driver, hex(addr))
        print("Call IOUserClient at 0x%x with 0x%x" % (self.state.addr, metaClass))
        if addr:
            # Check class name
            # TODO: what if the symbol resides in another binary?
            sym = self.project.loader.find_symbol(addr)
            if sym and sym.name.endswith("gMetaClassE"):
                clazz = demangle(sym.name)[:-len("::gMetaClass")]
                print(clazz, addr, sym.name)
                executor.addUserClient(self.state, clazz)

class ClientExecutor(MacExecutor):
    """symbolically execute Service::newUserClient to find all returned clients.
    """
    def __init__(self, proxy, binary, kext, entry):
        MacExecutor.__init__(self, proxy, binary, kext, entry, isConcolic=False)

        self.userClients = dict()

    def pre_execute(self, state):
        # newUserClient(this, task* owningTask, void* securityID, unsigned int type, IOUserClient** handler)
        typ = state.solver.BVS("type", 32, key=("newUserClient", "type"), eternal=True)
        state.regs.rcx = typ

        addr = self.getFuncAddr("IOUserClient::IOUserClient")
        self.proj.hook(addr, NewUserClient(executor=self), length=0)

        # IOService::NewUserClient
        addr = self.getFuncAddr("IOService::NewUserClient")
        self.proj.hook(addr, angr.SIM_PROCEDURES["stubs"]["PathTerminator"]())

    def post_execute(self, simgr):
        super(ClientExecutor, self).post_execute(simgr)
        return True

    def execute(self, simgr):
        while True:
            if len(simgr.active) == 0:
                break

            print(hex(simgr.active[0].addr), len(simgr.active))
            simgr = simgr.step()

        return simgr

    def addUserClient(self, state, userClient):
        variables = list(state.solver.get_variables("newUserClient", "type"))
        if len(variables) > 0:
            _, sym_cont = variables[0]
            cmin = state.solver.min(sym_cont)
            print("add one client %s: %d" % (userClient, cmin))
            if cmin in self.userClients and self.userClients[cmin] != userClient:
                raise Exception("inconsistent userClient between %s and %s" % \
                    (userClient, self.userClients[cmin]))
            self.userClients[cmin] = userClient

def _find_client(proxy, binary, kext, service, root=False):
    # if not service.access:
    #     logger.debug("service can not be accessed")
    #     return
    if service.newUserClient == 0:
        logger.debug("no newUserClient is provided")
        return False

    thread, lock = setup_debugger()
    userClients = dict()
    try:
        with proxy:
            logger.debug("set breakpoints for %s at 0x%x" % (service.metaClass, service.newUserClient))
            proxy.set_breakpoint(kext, service.newUserClient)

            # Make sure the VM is not stuck
            proxy.clear()

            # run PoC
            check_effect_service(service.metaClass, runInVM=True, root=root)
            # subprocess.run(["ssh", getRemoteAddr(), "~/testService %s 0" % service.metaClass])
            logger.debug("execute testService %s 0" % service.metaClass)

            proxy.wait_breakpoint()
            # Remove all breakpoints (recover from int3)
            proxy.remove_breakpoints()
            # proxy.step()

            executor = ClientExecutor(proxy, binary, kext, service.newUserClient)
            executor.run()
            userClients = executor.userClients

            # Continue to run because we will check whether we can access it in the VM.
            # proxy.continue_run()
    finally:
        lock.release()
        time.sleep(10)
        logger.debug("terminate debugger")
        thread.terminate()

        vmrun("reset")
        time.sleep(60)

    # Sometimes the VM gets stuck if we continue. Thus we check clients after the VM reboots.
    for typ, clazz in userClients.items():
        userClient = UserClient(className=clazz, type=typ)
        if check_effect_client(service.metaClass, typ, runInVM=True, root=False, timeout=5):
            userClient.access = True
        elif check_effect_client(service.metaClass, typ, runInVM=True, root=True, timeout=5):
            userClient.access = False
        else:
            logger.info("We cannot access %s:%s with selector %d" % (service.metaClass, clazz, typ))
            continue

        service.userClients.append(userClient)
        print(userClient.repr())

    proj = angr.Project(binary)
    for client in service.userClients:
        # locate key functions like externalMethods
        # Note user client may be defined in another binary.
        if not parse_client(proj, client):
            def find_class(binary, kext):
                proj = angr.Project(binary)
                if parse_client(proj, client):
                    return True
            iterate_kext(dir, find_class)

    # save results
    if len(service.userClients):
        dumps(os.path.join(ServicePath, service.metaClass), service)
        return True
    return False

def find_client(proxy, binary, kext, service, dir):
    """ A wrapper for the real function in order to capture exception and retry.
    """
    while True:
        try:
            # Try root here and later on we will test it against normal user.
            return _find_client(proxy, binary, kext, service, root=True)
        except ProxyException as e:
            logger.error("proxy error occurs! retrying...")

def find_default_client(binary, kext, service, dir):
    userClient = check_service_property(service.metaClass, "IOUserClientClass")
    if userClient:
        client = UserClient(className=userClient, type=0)
        if check_effect_client(service.metaClass, 0, runInVM=True, root=False):
            client.access = True
        elif check_effect_client(service.metaClass, 0, runInVM=True, root=True):
            client.access = False
        else:
            logger.info("We cannot access: %s:%s with default selector 0" % (service.metaClass, userClient))
            return False

        proj = angr.Project(binary)
        if not parse_client(proj, client):
            def find_class(binary, kext):
                proj = angr.Project(binary)
                if parse_client(proj, client):
                    return True
            iterate_kext(dir, find_class)

        service.userClients.append(client)
        dumps(os.path.join(ServicePath, service.metaClass), service)
        return True

def findAllService(binary):
    checked = set()
    services = []
    proj = angr.Project(binary)
    for sym in proj.loader.main_object.symbols:
        if "getMetaClass" not in sym.name:
            continue
        clazz, func = parse_signature(demangle(sym.name))
        if func == "getMetaClass" and clazz not in checked:
            checked.add(clazz)
            if check_effect_service(clazz, runInVM=True, root=False):
                services.append(clazz)
            elif check_effect_service(clazz, runInVM=True, root=True):
                services.append(clazz)
    return services

