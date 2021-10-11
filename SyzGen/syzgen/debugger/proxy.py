
import socket
import struct
import json
import logging

from angr_targets.concrete import ConcreteTarget
from angr.errors import SimConcreteMemoryError, SimConcreteRegisterError

logger = logging.getLogger(__name__)

class ProxyException(Exception):
    pass
    
def check_error(f):
    def wrapper(*args, **kwargs):
        reply = f(*args, **kwargs)
        if isinstance(reply, dict):
            if reply["errcode"] != 0:
                raise ProxyException("receive err: %d" % reply["errcode"])
        return reply

    return wrapper

class Proxy:
    def __init__(self, port=12345):
        self.serv = None
        self.sock = None
        self.port = port

    def __enter__(self):
        logger.info("start server, waiting for debugger to connect...")
        self.serve()
        logger.info("debugger connected")
        return self

    def __exit__(self, type, value, tb):
        self.pause()
        if self.sock:
            # only close the connection rather than terminating the server as `exit` does.
            self.sock.close()
            self.sock = None
        logger.info("please disconnect the debugger on the other side...")

    def serve(self):
        if self.serv is None:
            self.serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.serv.bind(('localhost', self.port))
            self.serv.listen(1)

        conn, addr = self.serv.accept()
        self.sock = conn
        print("connect to client")

    def exit(self):
        if self.sock:
            self.sock.close()
            self.sock = None
        if self.serv:
            self.serv.close()
            self.serv = None

    def send(self, data):
        request = json.dumps(data).encode()
        self.sock.sendall(struct.pack("<I", len(request)))
        self.sock.sendall(request)
        
    def recvn(self, nbytes):
        remain = nbytes
        ret = b''
        while remain > 0:
            data = self.sock.recv(remain)
            if not data:
                raise Exception("connection is broken")
            ret += data
            remain -= len(data)
        return ret
    
    def recv_reply(self, fmt="json"):
        size = self.recvn(4)
        size = struct.unpack("<I", size)[0]
        print("receive size:", size)
        if size == 0:
            return None
        
        data = self.recvn(size)
        if fmt == "json":
            return json.loads(data)
        return data
    
    @check_error
    def request(self, request, fmt="json"):
        self.send(request)
        return self.recv_reply(fmt=fmt)

    def pause(self):
        request = {
            "cmd": "pause"
        }
        self.request(request)

    def read_register(self, reg_name):
        request = {
            "cmd": "read reg",
            "reg": reg_name
        }
        reply = self.request(request)
        return reply["val"]

    def read_memory(self, address, nbytes, **kwargs):
        raise NotImplementedError

class DebuggerConcreteTarget(ConcreteTarget):
    def __init__(self, proxy):
        super(DebuggerConcreteTarget, self).__init__()
        self.proxy = proxy
        
    def read_register(self, register, **kwargs):
        try:
            val = self.proxy.read_register(register)
            if isinstance(val, str):
                if val.startswith("0x"):
                    return int(val, 16)
                return int(val)
            else:
                return val
        except:
            raise SimConcreteRegisterError("reg: %s" % register)
        
    def read_memory(self, address, nbytes, **kwargs):
        try:
            if 0xc0000000 <= address <= 0xd0000000: # special region for allocation
                return b'\x00'*nbytes
            return self.proxy.read_memory(address, nbytes, **kwargs)
        except:
            raise SimConcreteMemoryError("read mem addr: %x %d" % (address, nbytes))
        
    def exit(self):
        # self.sock.close()
        pass
