import time
import socket
import struct
import json
import argparse
import shlex

def catch_exception(f):
    def wrapper(*args, **kwargs):
        ret = {}
        try:
            data = f(*args, **kwargs)
            if data:
                ret.update(data)
            ret["errcode"] = 0
        except Exception as e:
            print(e)
            ret["errcode"] = 1
        return ret

    return wrapper

class Proxy:
    '''Generic proxy base'''

    def __init__(self):
        self.parser = self.create_options()
        self.sock = None

    def create_options(self):
        parser = argparse.ArgumentParser(prog=self.program, add_help=False)
        parser.add_argument("-c", "--connect", action="store_true", default=False, help="connect to client")
        parser.add_argument("-e", "--exit", action="store_true", default=False, help="quit")
        parser.add_argument("-r", "--restart", action="store_true", default=False, help="restart after pause")
        parser.add_argument("-t", "--test", action="store_true", default=False, help="testing")
        parser.add_argument("-f", "--find", action="store_true", default=False, help="helping function")
        parser.add_argument("-i", "--ip", default="localhost", help="ip address of client, default localhost")
        parser.add_argument("-h", "--help", action="store_true", default=False, help="show this help message")
        return parser

    def call_from_debugger(self, arg):
        command_args = shlex.split(arg)
        args = self.parser.parse_args(command_args)
        if args.connect:
            self.connect(args.ip)
        elif args.restart:
            self.serve_forever()
        elif args.exit:
            self.disconnect()
        elif args.test:
            self.test()
        elif args.find:
            self.set_breakpoint()
        elif args.help:
            self.parser.print_help()

    def test(self):
        raise NotImplementedError

    def set_breakpoint(self):
        pass

    def connect(self, ip):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((ip, 12345))
        print("successfully connect to the server")
        self.serve_forever()

    def disconnect(self):
        if self.sock:
            print("disconnect...")
            self.sock.close()
            self.sock = None

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
    
    def send(self, data):
        if data is None:
            self.sock.sendall(struct.pack("<I", 0))
        else:
            if isinstance(data, dict):
                data = json.dumps(data).encode()
            self.sock.sendall(struct.pack("<I", len(data)))
            self.sock.sendall(data)
        
    def serve_forever(self):
        if self.sock is None: return
        print("start listening")
        while True:
            size = self.recvn(4)
            size = struct.unpack("<I", size)[0]
            data = self.recvn(size)
            request = json.loads(data)
            if self.handle_command(request):
                break

    def handle_command(self, request):
        '''
        return: True to exit the loop
        '''
        cmd = request["cmd"]
        if cmd == "read reg":
            self.send(self.read_register(request))
        elif cmd == "read mem":
            reply = self.read_memory(request)
            if "val" in reply and len(reply["val"]) > 0:
                self.send(reply["val"])
            else:
                self.send(None)
        elif cmd == "pause":
            self.send({"errcode": 0})
            return True
        elif cmd == "exit":
            self.disconnect()
            return True

        return False



