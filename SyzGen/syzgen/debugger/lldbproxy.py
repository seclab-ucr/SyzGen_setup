
import logging
import pexpect
import os
import subprocess
import re

from functools import lru_cache
from multiprocessing import Process, Lock
from threading import Thread

from .proxy import Proxy
from ..utils import getConfigKey, getRemoteAddr

logger = logging.getLogger(__name__)

FIELD_OFFSET_REG = re.compile(r"^\((?P<type>.+)\) \$0 = (?P<value>0x[\da-f]+)$")

class LLDBProxy(Proxy):
    '''LLDB Proxy used by angr to retrieve code and data.
    '''

    def __init__(self, port=12345):
        super(LLDBProxy, self).__init__(port=port)

    def __enter__(self):
        logger.info("start server, waiting for debugger to connect...")
        self.serve()
        logger.info("debugger connected")
        return self

    def __exit__(self, type, value, tb):
        self.pause()
        if self.sock:
            # onlt close the connection rather than terminating the server as `exit` does.
            self.sock.close()
            self.sock = None
        logger.info("please disconnect the debugger on the other side...")

    def read_register(self, reg_name):
        request = {
            "cmd": "read reg",
            "reg": reg_name
        }
        reply = self.request(request)
        return reply["val"]

    def read_memory(self, addr, size, task=None):
        request = {
            "cmd": "read mem",
            "addr": addr,
            "size": size
        }
        if task is not None:
            request["task"] = task
        return self.request(request, fmt="binary")
    
    def pause(self):
        request = {
            "cmd": "pause"
        }
        self.request(request)
        
    def find_functions_addr(self, names):
        request = {
            "cmd": "find func",
            "names": names
        }
        reply = self.request(request)
        return reply["funcs"]

    def find_function_name(self, addr):
        request = {
            "cmd": "find name",
            "addr": addr
        }
        reply = self.request(request)
        return reply["name"]

    def find_global_variable(self, name):
        request = {
            "cmd": "find var",
            "name": name
        }
        reply = self.request(request)
        return reply["addr"]
    
    def read_kext_mapping(self):
        request = {
            "cmd": "showallkexts"
        }
        reply = self.request(request)
        ret = reply["kexts"]
        return sorted(ret, key=lambda x: x[0])

    def read_task(self, name):
        request = {
            "cmd": "showtask",
            "name": name
        }
        reply = self.request(request)
        return reply["task"]

    def set_task(self, name):
        request = {
            "cmd": "set target",
            "target": name
        }
        self.request(request)

    def wait_breakpoint(self):
        request = {
            "cmd": "wait"
        }
        self.request(request)

    def continue_run(self):
        request = {
            "cmd": "continue"
        }
        self.request(request)

    def clear(self):
        request = {
            "cmd": "clear"
        }
        self.request(request)

    def step(self):
        request = {
            "cmd": "step"
        }
        self.request(request)

    def remove_breakpoints(self):
        request = {
            "cmd": "rm bp"
        }
        self.request(request)

    def set_breakpoint(self, kext, addr):
        request = {
            "cmd": "set bp",
            "kext": kext,
            "addr": addr
        }
        self.request(request)


class LLDBDebugger(Thread):
    '''LLDB debugger used to communicate with debugger and send commands.
    '''

    def __init__(self, kernel):
        super().__init__(daemon=True)

        self.kernel = kernel
        self.stop = False

        if not os.path.exists(kernel):
            raise FileNotFoundError(kernel)

    def run(self):
        try:
            logger.debug("spawn lldb")
            lldb = pexpect.spawn("lldb %s" % self.kernel, timeout=30)
            lldb.expect("\\(lldb\\)")
            # lldb.expect("\\(lldb\\)")
            outs = lldb.before
            print(outs)

            # For unknown reason, we have to invoke 'script' in advance.
            lldb.sendline("script")
            lldb.expect(">>>")
            outs = lldb.before
            print(outs)

            lldb.sendline("quit()")
            lldb.expect("\\(lldb\\)")
            print(lldb.before)
            # lldb.expect("\\(lldb\\)")
            # print(lldb.before)

            lldb.sendline("command script import %s" % os.path.join(os.getcwd(), "debug.py"))
            lldb.expect("\\(lldb\\)")
            print(lldb.before)
            # lldb.expect("\\(lldb\\)")
            # print(lldb.before)

            ip = getConfigKey("ip")
            logger.debug("kdp-remote %s" % ip)
            lldb.sendline("kdp-remote %s" % ip)
            lldb.expect("stopped")
            print(lldb.before)

            logger.debug("proxy -c")
            lldb.sendline("proxy -c")

            while not self.stop:
                lldb.expect([pexpect.TIMEOUT, pexpect.EOF], timeout=1)
            logger.debug("return from proxy -c")
        finally:
            lldb.close()
            lldb.terminate(force=True)

    def terminate(self):
        self.stop = True

    @staticmethod
    @lru_cache(maxsize=None)
    def fieldOffset(fieldName: str, structName: str, object_path: str) -> int:
        cmds = [
            "lldb",
            object_path,
            "-o",
            f"p &((({structName}*)0)->{fieldName})",
            "--batch",
        ]
        ret = subprocess.run(cmds, stdout=subprocess.PIPE)
        for line in ret.stdout.split(b'\n'):
            line = line.decode('utf-8')
            if "$0" in line:
                print(line)
                m = FIELD_OFFSET_REG.match(line)
                if m:
                    return int(m.group("value"), 16)
        raise Exception(f"Failed to get the offset of {fieldName} from {structName}")


def launch_lldb(kernel, lock):
    lldb = LLDBDebugger(kernel)
    # time.sleep(2)  # wait for server to start
    lldb.start()

    lock.acquire(block=True)
    lldb.terminate()
    lldb.join()

def run_debugger(kernel: str):
    lock = Lock()
    lock.acquire()

    t = Process(target=launch_lldb, args=(kernel, lock, ))
    t.start()
    return t, lock

def setup_debugger():
    subprocess.run(["ssh", getRemoteAddr(), "sudo dtrace -w -n \"BEGIN { breakpoint(); }\""])
    # time.sleep(10)  # wait 10s to make it taking effect
    logger.debug("suspend VM")

    return run_debugger(getConfigKey("kernel"))


def TestFieldOffset():
    print(LLDBDebugger.fieldOffset(
        "structureOutputSize",
        "IOExternalMethodArguments",
        "/Library/Developer/KDKs/KDK_10.15.4_19E287.kdk/System/Library/Kernels/kernel.development",
    ))