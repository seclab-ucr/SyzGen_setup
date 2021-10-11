
import struct
import logging
import os
import json
import pickle

from angr.calling_conventions import SimRegArg, SimStackArg

from ..utils import dumps
from .optimize import Context, infer_dependence_input, infer_dependence_output, infer_extra_dependence, refine_dependence
from .types import Type, PtrType, BufferType, ConstType, StructType, ResourceType, int2bytes, \
    Constant, StringType, NullPointer

logger = logging.getLogger(__name__)

class Argument:
    def __init__(self, data):
        if data["type"] == "SimRegArg":
            arg = SimRegArg(data["reg_name"], data["size"])
        elif data["type"] == "SimStackArg":
            arg = SimStackArg(data["stack_offset"], data["size"])
        self.arg = arg
        self.is_ptr = data["is_ptr"]

    def get_value(self, state):
        return self.arg.get_value(state)

class Syscall:
    def __init__(self, callName, subName):
        self.CallName = callName
        self.SubName = subName

        self.args = []
        self.arg_names = []

        self._counter = 0
        self.status = 0
        self.numOfBB = 0

    @property
    def Name(self):
        if self.SubName and len(self.SubName) > 0:
            return "%s$%s" % (self.CallName, self.SubName)
        return self.CallName

    def assignNewName(self, prefix):
        # Note: the rule for generating names is critical as we rely on the pattern to distinguish 
        # special flags.
        self._counter += 1
        if self.CallName == "syz_IOConnectCallAsyncMethod":
            return "async_%s_%s_%d" % (self.SubName, prefix, self._counter)
        return "%s_%s_%d" % (self.SubName, prefix, self._counter)

    def resetName(self):
        """All self-assigned name should be reset as we may want to re-name the syscall.
        """
        self._counter = 0
        for arg in self.args:
            arg.resetName(self.SubName)

    def validate(self):
        if self.arg_names and len(self.arg_names) == len(self.args):
            for i in range(len(self.args)):
                self.args[i].typename = self.arg_names[i]
        return True

    def visit(self, ctx, func, isOffset=False):
        """ Visitor to traverse all arguments in a DFS manner.
        """
        for i, arg in enumerate(self.args):
            ctx.arg = arg.typename
            ctx.path.append(i)
            if arg.visit(ctx, func, isOffset=isOffset):
                break
            ctx.path.pop()

    def refine(self, other):
        for i in range(len(self.args)):
            self.args[i] = self.args[i].refine(other.args[i])
        self.validate()

    def refine_type(self, ctx, func, isOffset=False):
        """ Visitor to traverse all arguments and allow modification of them.
        """
        for i, arg in enumerate(self.args):
            ctx.arg = arg.typename
            ctx.path.append(i)
            self.args[i] = arg.refine_type(ctx, func, isOffset=isOffset)
            ctx.path.pop()
        self.validate()

    def simplify(self, other):
        """Refine current model according to passed model
        """
        self.CallName = other.CallName
        self.SubName = other.SubName
        for i, arg in enumerate(self.args):
            self.args[i] = arg.simplify(other.args[i])
        self.validate()

    def equal(self, other):
        if self.CallName != other.CallName:
            return False
        for i in range(len(self.args)):
            if not self.args[i].equal(other.args[i]):
                return False
        return True

    def generateTemplate(self, f):
        func = "%s(%s)"
        args = []
        for arg in self.args:
            # Note syzkaller assume the size for syscalls' argument is fixed.
            # Therefore, no need for const to specify the size.
            typ, name = arg.generateTemplate(self, PtrType.DirIn, f, top=True)
            args.append("%s %s" % (name, typ))
        f.write("%s(%s)\n" % (self.Name, ", ".join(args)))

    def repr(self):
        ret = self.Name + "\n"
        ret += "status: %d\n" % self.status
        for arg in self.args:
            ret += "%s:\n" % arg.typename
            ret += arg.repr()
        return ret

    def toArgs(self):
        # Convert it data that can be later transformed into testcase by syzkaller
        args = []
        for each in self.args:
            args.append(each.toJson())
        return {"group": self.Name, "args": args}

    def toJson(self):
        ret = {
            "CallName": self.CallName,
            "SubName": self.SubName,
            "arg_names": self.arg_names,
            "counter": self._counter,
            "status": self.status,
            "numOfBB": self.numOfBB,
            "args": []
        }
        for each in self.args:
            ret["args"].append(each.toJson())
        return ret

    def copy(self):
        obj = pickle.loads(pickle.dumps(self))
        obj.resetName()
        return obj

    @staticmethod
    def load(data):
        types = {
            "ServiceOpen": ServiceOpen,
            "ServiceClose": ServiceClose,
            "syz_IOConnectCallMethod": IOConnectCallMethod,
            "syz_IOConnectCallAsyncMethod": IOConnectCallAsyncMethod
        }

        if data["CallName"] not in types:
            raise Exception("Unknown syscall name %s" % data["CallName"])

        syscall = types[data["CallName"]](data["SubName"])
        syscall.arg_names = data["arg_names"]
        syscall._counter = data["counter"]
        syscall.status = data["status"]
        syscall.numOfBB = data["numOfBB"]
        for i in range(len(data["args"])):
            syscall.args[i] = Type.construct(data["args"][i])
        syscall.validate()
        return syscall

class ServiceOpen(Syscall):
    def __init__(self, subname):
        super(ServiceOpen, self).__init__("syz_IOServiceOpen", subname)

        self.args.append(PtrType({"ref": StringType({"data": [0]}).toJson()}, typename="service"))
        self.args.append(BufferType({"data": int2bytes(0, 4)}, typename="selector"))
        self.args.append(PtrType({"ref": ResourceType({"name": "io_connect_t", "data": int2bytes(0, 8)}).toJson()}, typename="port"))
        self.arg_names = ["service", "selector", "port"]
        self.validate()

    @staticmethod
    def create(serviceName, client):
        syscall = ServiceOpen(client.metaClass)
        syscall.service = PtrType({"ref": StringType({"data": [ord(e) for e in serviceName], "values": [serviceName]}).toJson()})
        syscall.selector = Constant(client.type, 4, "selector")
        port = ResourceType({"name": "%s_port" % client.metaClass, "parent": "io_connect_t", \
            "data": int2bytes(0, 8)})
        syscall.port = PtrType({"ref": port.toJson()}, typename="port")
        syscall.validate()
        return syscall

    def validate(self):
        super(ServiceOpen, self).validate()

        self.service.dir = PtrType.DirIn
        self.port.dir = PtrType.DirOut
        return True

    @property
    def service(self):
        return self.args[0]

    @service.setter
    def service(self, val):
        self.args[0] = val

    @property
    def selector(self):
        return self.args[1]

    @selector.setter
    def selector(self, val):
        self.args[1] = val

    @property
    def port(self):
        return self.args[2]

    @port.setter
    def port(self, val):
        self.args[2] = val

class ServiceClose(Syscall):
    def __init__(self):
        super(ServiceClose, self).__init__("syz_IOServiceClose", "")

        self.args.append(BufferType({"data": int2bytes(0, 8)}, typename="port"))
        self.arg_names = ["port"]

    @staticmethod
    def create(port):
        self.port = BufferType({"data": int2bytes(port, 8)}, typename="port")

    @property
    def port(self):
        return self.args[0]

    @port.setter
    def port(self, val):
        self.args[0] = val

class IOConnectCallMethod(Syscall):
    """kern_return_t IOConnectCallMethod(mach_port_t connection, uint32_t selector, const uint64_t *input, 
    uint32_t inputCnt, const void *inputStruct, size_t inputStructCnt, uint64_t *output, uint32_t *outputCnt, 
    void *outputStruct, size_t *outputStructCnt);
    """
    MAXIMUM_INPUTCNT = 0x10
    MAXIMUM_OUTPUTCNT = 0x10

    def __init__(self, subname):
        super(IOConnectCallMethod, self).__init__("syz_IOConnectCallMethod", subname)

        # mach_port_t connection
        self.args.append(ResourceType({"name": "io_connect_t", "data": int2bytes(0, 8)}, typename="connection"))
        # uint32_t selector
        self.args.append(BufferType({"data": int2bytes(0, 4)}, typename="selector"))
        # uint64_t *input
        fields = []
        for i in range(IOConnectCallMethod.MAXIMUM_INPUTCNT):
            fields.append(BufferType({"data": [0xff]*8}, i*8).toJson())
        self.args.append(PtrType({"ref": StructType({"fields": fields, "isArray": True}, 0).toJson()}, typename="input"))
        # uint32_t inputCnt
        self.args.append(BufferType({"data": int2bytes(IOConnectCallMethod.MAXIMUM_INPUTCNT, 4)}, typename="inputCnt"))
        # void *inputStruct
        self.args.append(PtrType({"ref": BufferType({"data": [0xff]*1024}).toJson()}, typename="inputStruct"))
        # size_t inputStructCnt
        self.args.append(BufferType({"data": int2bytes(1024, 4)}, typename="inputStructCnt"))
        # uint64_t *output
        fields = []
        for i in range(IOConnectCallMethod.MAXIMUM_OUTPUTCNT):
            fields.append(BufferType({"data": [0xff]*8}, i*8).toJson())
        self.args.append(PtrType({"ref": StructType({"fields": fields, "isArray": True}).toJson()}, typename="output"))
        # uint32_t *outputCnt
        self.args.append(PtrType({"ref": BufferType({"data": int2bytes(IOConnectCallMethod.MAXIMUM_OUTPUTCNT, 4)}).toJson()}, typename="outputCnt"))
        # void *outputStruct
        self.args.append(PtrType({"ref": BufferType({"data": [0xff]*1024}).toJson()}, typename="outputStruct"))
        # size_t *outputStructCnt
        self.args.append(PtrType({"ref": BufferType({"data": int2bytes(1024, 4)}).toJson()}, typename="outputStructCnt"))

        self.arg_names = ["connection", "selector", "input", "inputCnt", "inputStruct", "inputStructCnt", \
            "output", "outputCnt", "outputStruct", "outputStructCnt"]
        self.validate()

    def validate(self):
        super(IOConnectCallMethod, self).validate()

        if self.input.type == "ptr":
            self.input.ref.isArray = True
            self.input.dir = PtrType.DirIn
            self.inputCnt.path = [2]
            self.inputCnt.bitSize = 64
            # if self.inputCnt.type == "len":
            #     self.inputCnt.bitSize = 64
        if self.inputStruct.type == "ptr":
            self.inputStruct.dir = PtrType.DirIn
            self.inputStructCnt.path = [4]
        if self.output.type == "ptr":
            self.output.ref.isArray = True
            self.output.dir = PtrType.DirOut
        if self.outputCnt.type == "ptr":
            self.outputCnt.dir = PtrType.DirIn
            self.outputCnt.ref.path = [6]
            self.outputCnt.ref.bitSize = 64
            # if self.outputCnt.ref.type == "len":
            #     self.outputCnt.ref.bitSize = 64
        if self.outputStruct.type == "ptr":
            self.outputStruct.dir = PtrType.DirOut
        if self.outputStructCnt.type == "ptr":
            self.outputStructCnt.dir = PtrType.DirIn
            self.outputStructCnt.ref.path = [8]
        return True

    def refine_cmd(self, selector, offset, size, cmd=None):
        """ If we know the field used as the command handler, we could further refine the 
        model by concretizing the coorresponding field.
        """
        def concretize(ctx, typ):
            if ctx.arg != selector.typename:
                return typ

            # only analyze the first layer
            if (len(ctx.path) == 2 and ctx.parent.type == "ptr") or \
                (len(ctx.path) == 3 and ctx.parent.type == "struct"):
                # ptr->buffer or ptr->struct->buffer
                if typ.offset <= offset and typ.offset + typ.size >= offset + size:
                    if typ.size == size and typ.type == "const":
                        ctx.ret = typ.getData()
                        return typ
                    if typ.type != "buffer":
                        return typ

                    # split the buffer
                    fields = []
                    off = offset - typ.offset
                    for i, (start, end) in enumerate([(0, off), (off, off+size), (off+size, typ.size)]):
                        if start == end:
                            continue
                        data = typ.toJson()
                        data["data"] = typ.data[start:end]
                        data["offset"] = start + typ.offset
                        data["typename"] = None # reset the typename as it may split into multiple objs.
                        if i == 1:
                            data["type"] = "const"
                            if cmd is not None:
                                data["data"] = int2bytes(cmd, size)
                            ctx.ret = int.from_bytes(data["data"], "little")
                        fields.append(Type.construct(data))
                    if len(fields) == 1:
                        fields[0] = typ.typename  # inherit parent's name
                        return fields[0]
                    return fields

            return typ

        ctx = Context()
        self.refine_type(ctx, concretize)
        if cmd is not None and ctx.ret != cmd:
            print(cmd, ctx.ret)
            raise Exception("incorrect cmd handler")
        return ctx.ret

    def getCmdHandler(self, sym, cmd=None):
        if sym.op == "BVS":
            if sym._encoded_name.startswith(b'selector_'):
                if self.selector.type != "const":
                    if cmd is None:
                        raise Exception("cmd is None")
                    self.selector = Constant(cmd, 4, "selector")
                return self.selector.getData()
            else:
                raise Exception("not implemented: getCmdHandler for %s" % sym)
        if sym.op == "Extract" and sym.args[2].op == 'BVS':
            left, right = (sym.args[2].length-sym.args[0]-1)//8, (sym.args[2].length-sym.args[1])//8
            if sym.args[2]._encoded_name.startswith(b"structInput"):
                return self.refine_cmd(self.inputStruct, left, right-left, cmd=cmd)

        raise Exception("not implemented: getCmdHandler for %s" % sym)

    @property
    def connection(self):
        return self.args[0]

    @connection.setter
    def connection(self, val):
        self.args[0] = val

    @property
    def selector(self):
        return self.args[1]

    @selector.setter
    def selector(self, val):
        self.args[1] = val

    @property
    def input(self):
        return self.args[2]

    @input.setter
    def input(self, val):
        self.args[2] = val

    @property
    def inputCnt(self):
        return self.args[3]

    @inputCnt.setter
    def inputCnt(self, val):
        self.args[3] = val

    @property
    def inputStruct(self):
        return self.args[4]

    @inputStruct.setter
    def inputStruct(self, val):
        self.args[4] = val

    @property
    def inputStructCnt(self):
        return self.args[5]

    @inputStructCnt.setter
    def inputStructCnt(self, val):
        self.args[5] = val

    @property
    def output(self):
        return self.args[6]

    @output.setter
    def output(self, val):
        self.args[6] = val

    @property
    def outputCnt(self):
        return self.args[7]

    @outputCnt.setter
    def outputCnt(self, val):
        self.args[7] = val

    @property
    def outputStruct(self):
        return self.args[8]

    @outputStruct.setter
    def outputStruct(self, val):
        self.args[8] = val

    @property
    def outputStructCnt(self):
        return self.args[9]

    @outputStructCnt.setter
    def outputStructCnt(self, val):
        self.args[9] = val

class IOConnectCallAsyncMethod(IOConnectCallMethod):
    def __init__(self, subname):
        super(IOConnectCallAsyncMethod, self).__init__(subname)
        self.CallName = "syz_IOConnectCallAsyncMethod"

class Log:
    """
    Combine related logs into one structure.
    """
    def __init__(self, pid=0, port=0, selector=-1, ranges=None, input=[], inputCnt=0, inputStruct=[],
        inputStructCnt=0, output=[], outputCnt=0, outputStruct=[], outputStructCnt=0, call="IOConnectCallMethod"):
        self.pid = pid
        self.port = port
        self.selector = selector
        self.ranges = ranges if ranges else dict()
        self.input = input
        self.inputCnt = inputCnt
        self.inputStruct = inputStruct
        self.inputStructCnt = inputStructCnt
        self.output = output
        self.outputCnt = outputCnt
        self.outputStruct = outputStruct
        self.outputStructCnt = outputStructCnt
        self.call = call

    def scanPointer(self, ptr, data):
        i = 0
        raw_data = []
        fields = []
        while i < len(data):
            buf = data[i:i+8]
            if len(buf) < 8:
                raw_data += buf
                break
            p = struct.unpack("<Q", bytes(buf))[0]
            if p in self.ranges:
                # print(self.ranges, ptr)
                field = self.scanPointer(p, self.ranges[p]["data"])
                if len(raw_data) != 0:
                    fields.append({"type": "buffer", "data": raw_data})
                    raw_data = []
                fields.append(field)
            else:
                raw_data += buf
            i += 8

        if len(raw_data) != 0:
            fields.append({"type": "buffer", "data": raw_data})

        if len(fields) == 0:
            # Null Pointer
            return {"type": "const", "data": int2bytes(0, 8)}
        if len(fields) == 1:
            return {"type": "ptr", "ptr": ptr, "ref": fields[0]}
        return {"type": "ptr", "ptr": ptr, "ref": {"type": "struct", "fields": fields}}

    def construct(self):
        self.input = self.scanPointer(0, self.input)
        self.input["typename"] = "input"
        self.inputStruct = self.scanPointer(0, self.inputStruct)
        self.inputStruct["typename"] = "inputStruct"
        self.output = self.scanPointer(0, self.output)
        self.output["typename"] = "output"
        self.outputStruct = self.scanPointer(0, self.outputStruct)
        self.outputStruct["typename"] = "outputStruct"
        # construct syscall
        syscall = None
        if self.call == "IOConnectCallMethod":
            syscall = IOConnectCallMethod("tmp")
        elif self.call == "IOConnectCallAsyncMethod":
            syscall = IOConnectCallAsyncMethod("tmp")
        else:
            raise Exception("unkonnw call %s" % self.call)

        syscall.connection = Constant(self.port, 8, "connection")
        syscall.selector = Constant(self.selector, 4, "selector")
        syscall.input = Type.construct(self.input)
        # Note: if the count is zero, we assume it will always be zero.
        if self.inputCnt:
            syscall.inputCnt = BufferType({"data": int2bytes(self.inputCnt, 4)}, typename="inputCnt")
        else:
            syscall.inputCnt = Constant(0, 4, "inputCnt")
        syscall.inputStruct = Type.construct(self.inputStruct)
        if self.inputStructCnt:
            syscall.inputStructCnt = BufferType({"data": int2bytes(self.inputStructCnt, 4)}, typename="inputStructCnt")
        else:
            syscall.inputStructCnt = Constant(0, 4, "inputStructCnt")

        syscall.output = Type.construct(self.output)
        if self.outputCnt:
            syscall.outputCnt = PtrType({"ref": BufferType({"data": int2bytes(self.outputCnt, 4)}).toJson()}, typename="outputCnt")
        else:
            syscall.outputCnt = NullPointer(0, "outputCnt")
        syscall.outputStruct = Type.construct(self.outputStruct)
        if self.outputStructCnt:
            syscall.outputStructCnt = PtrType({"ref": BufferType({"data": int2bytes(self.outputStructCnt, 4)}).toJson()}, typename="outputStructCnt")
        else:
            syscall.outputStructCnt = NullPointer(0, "outputStructCnt")
        syscall.validate()
        return syscall

    def toTestcase(self):
        ipt = {
            "port": self.port,
            "pid": self.pid,
            "selector": self.selector,
            "scalarInput": self.input,
            "scalarInputCnt": self.inputCnt,
            "inputStruct": self.inputStruct,
            "inputStructSize": self.inputStructCnt,
            "scalarOutputCnt": self.outputCnt,
            "outputStructSize": self.outputStructCnt
        }
        addrs = []
        for addr, data in self.ranges.items():
            addrs.append({"pid": self.pid, "size": len(data), "addr": addr, "data": data})
        opt = {
            "pid": self.pid,
            "outputStructSize": len(self.outputStruct),
            "outputStruct": self.outputStruct,
            "scalarOutputCount": len(self.output)//8,
            "scalarOutput": self.output
        }
        ret = json.dumps(ipt) + "\n"
        if addrs: ret += "\n".join([json.dumps(each) for each in addrs])
        if self.outputStruct or self.output:
            ret += json.dumps(opt) + "\n"
        return ret

def parse_log(log):
    ents = []
    with open(log, "r") as fp:
        ent = None
        for line in fp:
            dat = json.loads(line.strip())
            if "port" in dat:
                ent = Log()  # New entry
                ent.pid = dat["pid"]
                ent.port = dat["port"]
                ent.selector = dat["selector"]
                
                ent.input = dat["scalarInput"]
                ent.inputCnt = dat["scalarInputCnt"]
                ent.inputStructCnt = dat["inputStructSize"]
                ent.inputStruct = dat["inputStruct"]
                ent.outputCnt = dat["scalarOutputCnt"]
                ent.outputStructCnt = dat["outputStructSize"]
                if "call" in dat:
                    ent.call = data["call"]

                ents.append(ent)
            elif "addr" in dat:
                if dat["pid"] != ent.pid:
                    print("inconsistent pid")
                    print(ent, dat)
                ent.ranges[dat["addr"]] = dat
            elif "outputStruct" in dat:
                if dat["pid"] != ent.pid:
                    print("inconsistent pid")
                    print(ent, dat)
                ent.output = dat["scalarOutput"]
                ent.outputStruct = dat["outputStruct"]

    return ents

def refine_model_with_log(logdir, model, client):
    """Given some logs, we could construct the skeleton of input structures and infer dependences
    based on input-output pair match. Refine our initial model with nested pointers and dependences.
    """
    # collect logs
    all_logs = dict()
    for name in os.listdir(logdir):
        print(name)
        if name.endswith(".log") and name.startswith("kernel_hook"):
            logger.debug("parsing %s" % name)
            ents = parse_log(os.path.join(logdir, name))
            all_logs[name] = ents
    
    #  refine current model
    all_syscalls = dict()
    for filename, ents in all_logs.items():
        all_syscalls[filename] = [ent.construct() for ent in ents]
        for syscall in all_syscalls[filename]:
            cmd = syscall.getCmdHandler(model.selector)
            # At beginning, each command only has one template
            # print(syscall.repr())
            model.methods[cmd][0].refine(syscall)

    # save parsed logs
    for name, ents in all_syscalls.items():
        dumps(os.path.join(logdir, "out_%s" % name), ents)

    for filename, ents in all_syscalls.items():
        for ent in ents:
            cmd = ent.getCmdHandler(model.selector)
            ent.simplify(model.methods[cmd][0])

    dependences = []
    dependences += infer_dependence_input(all_syscalls, model)
    dependences += infer_dependence_output(all_syscalls, model)
    dependences += infer_extra_dependence(all_syscalls, model, os.path.join(logdir, "extra_dep.json"))
    tmp = dict()
    for each in dependences:
        if each not in tmp:
            tmp[each] = True
    dependences = list(tmp.keys())

    num = 0
    types = dict()
    resources = dict()
    connections = dict()
    for dep in dependences:
        if dep.outPath is None:
            continue

        if dep.outPath not in types:
            while True:
                # find an available name
                typename = "%s_connection_%d" % (client.metaClass, num)
                if typename not in resources:
                    break
                num += 1
            item = {"name": typename}
            item["isExtra"] = True if dep.outPath.index < 0 else False
            types[dep.outPath] = item
            resources[typename] = True
            connections[typename] = dep.outPath.type.size * 8

    print("connections:", connections)
    refine_dependence(model, dependences, types)
    return types
