
import os
import subprocess
import logging
import shutil
import json

from ..utils import check_output, dumps, loads, getConfigKey
from ..config import ModelPath, TestCasePath
from .interface import IOConnectCallMethod, refine_model_with_log, ServiceOpen, ServiceClose, Syscall
from .types import BufferType, ResourceType, ConstType, int2bytes, StringType, \
    Constant, NullPointer, Pointer, Buffer, PtrType, BufferOffset, StructType, \
    Size2Type, Const2Type, SimplifyError, LenType, ArrayType, Type
from .optimize import Context, reduce_struct, findLenByOffset, findFieldByOffset

logger = logging.getLogger(__name__)

class Model:
    def __init__(self, selector):
        self.selector = selector
        # methods = {"cmd": [sub_syscall1, ...]}
        # Each cmd may corresponds to multiple input structure and thus multiple syscall models.
        self.methods = dict()
        self.async_methods = dict()

def buildPocFromSyz(filepath, outpath=None):
    syzkaller = getConfigKey("syzkaller")
    cmds = ["%s/bin/syz-prog2c" % syzkaller, "-prog", filepath]
    with open("poc.c", "w") as fp:
        subprocess.run(cmds, stdout=fp, check=True)

    cmds = ["gcc", "poc.c", "-o", "poc", "-framework", "IOKit"]
    logger.debug(" ".join(cmds))
    subprocess.run(cmds, check=True)
    # Give entitlement
    cmds = ["sh", "./autosign.sh", "../poc"]
    logger.debug("%s (%s)" % (" ".join(cmds), os.path.join(os.getcwd(), "libs")))
    subprocess.run(cmds, check=True, cwd=os.path.join(os.getcwd(), "libs"))

    if outpath:
        shutil.move("poc", outpath)

def genServicePoc(serviceName, client):
    """
    IOServiceOpen(serviceName, type, &connection)
    kern_return_t IOConnectCallMethod(mach_port_t connection, uint32_t selector, 
        const uint64_t *input, uint32_t inputCnt, const void *inputStruct, 
        size_t inputStructCnt, uint64_t *output, uint32_t *outputCnt, 
        void *outputStruct, size_t *outputStructCnt);
    """
    with open("poc.syz", "w") as fp:
        fp.write('syz_IOServiceOpen(&(0x7f0000000000)=\'%s\\x00\', 0x%x, &(0x7f0000000000)=<r0=>0x0)\n' % \
            (serviceName, client.type))
        fp.write("syz_IOConnectCallMethod(r0, 0, &(0x7f0000001000), 0x10, &(0x7f0000002000), 0x400, " + \
            "&(0x7f0000003000), &(0x7f0000004000)=0x10, &(0x7f0000005000), &(0x7f0000006000)=0x400)\n")
        fp.write("syz_IOServiceClose(r0)")

    buildPocFromSyz("poc.syz")

def reduce_lenType(interface, finalize):
    # TODO: check this carefully!!
    def refine(ctx, typ):
        if isinstance(typ, BufferType) and typ.path is not None:
            ptr = findFieldByOffset(interface, typ.path)
            if ptr and ptr.typename and ptr.ref:
                data = typ.toJson()
                data["lenField"] = ptr.typename
                if typ.type == "const":
                    size = typ.getData()
                    if size == 0:
                        return typ
                    if not ptr.ref.isArray:
                    #     if ptr.ref.type != "struct" and size != 1:
                    #         print(ptr.ref.repr())
                    #         print(size)
                    #         raise Exception("inconsistent array size")
                    # else:
                        if size != ptr.ref.size:
                            print(interface.repr())
                            print(typ.repr())
                            print(ptr.repr())
                            # if size < ptr.ref.size:
                            #     raise Exception("inconsistent size")
                    if ptr.ref.type == "string":
                        print("find a lenType")
                        print(typ.repr())
                        print(ptr.repr())
                        data["max"] = data["min"] = 0
                        return LenType(data, typ.offset, typename=typ.typename)
                elif typ.type == "buffer":
                    data["max"] = data["min"] = 0
                    return LenType(data, typ.offset, typename=typ.typename)
                elif typ.type == "range":
                    # FIXME: range should also become lenType?
                    if ptr.ref.type == "string" and typ.min < 1024:
                        # Since we cannot have limits on the string, let's keep using range.
                        return typ

                    data["max"] = typ.max
                    data["min"] = typ.min
                    return LenType(data, typ.offset, typename=typ.typename)
                elif typ.type == "flag":
                    data["max"] = max(typ.values)
                    data["min"] = min(typ.values)
                    return LenType(data, typ.offset, typename=typ.typename)
                # if ptr.optional: # union has different sizes
                #     return LenType({"size": typ.size, "lenField": ptr.typename}, typ.offset)
        if ctx.parent and ctx.parent.type == "ptr":
            parent, lenType = findLenByOffset(interface, ctx.path[:-1])
            if lenType:
                if typ.type == "buffer" and typ.size == 1024 and finalize:
                    typ.size = 0
                    typ.data = []
                # if typ.type == "array" and lenType.type in ["len", "range", "flag", "buffer"]:
                #     return Constant(0, 4, typ.typename)

                if typ.type == "struct" and lenType.type in ["len", "range", "flag", "buffer", "const"]:
                    # It must be of variable length.
                    # Note: if it is finalized, we use a large buffer as the initial length
                    # (min = max = 1024).
                    minLen, maxLen = (0, 1024) if finalize else (1024, 1024)
                    if lenType.type == "len" or lenType.type == "range":
                        if lenType.max == 0:
                            return Constant(0, 4, typ.typename)

                        if finalize:
                            minLen, maxLen = lenType.min, lenType.max
                        else:
                            # Provide the maximum length if it is not finalized (We also set a threshold 1024).
                            v = min(lenType.max, 1024*8//lenType.bitSize)
                            minLen, maxLen = v, v
                    elif lenType.type == "flag":
                        if max(lenType.values) == 0:
                            return Constant(0, 4, typ.typename)

                        if finalize:
                            minLen, maxLen = min(lenType.values), max(lenType.values)
                        else:
                            v = min(max(lenType.values), 1024*8//lenType.bitSize)
                            minLen, maxLen = v, v
                    elif lenType.type == "const":
                        v = lenType.getData()
                        minLen, maxLen = v, v
                        
                    # else: # buffer
                    if lenType.typename == "inputCnt" or \
                        (parent and parent.typename == "outputCnt"):
                        maxLen = min(maxLen, 16)
                        minLen = min(minLen, 16)
                    # print("debug", lenType.typename, minLen, maxLen)
                    # TODO: if minLen == maxLen we do not use array.
                    if minLen == maxLen and not all([each.equal(typ.fields[0]) for each in typ.fields[1:]]):
                        pass
                    elif lenType.bitSize > 8: # and lenType.bitSize not in [16, 32, 64]:
                        # It might be an array of structure or scalarInput
                        fields = []
                        totalSize = 0
                        repeat = typ.fields[0].size == lenType.bitSize//8
                        if repeat:
                            # If the first field has the same size of the bitSize, we probably have a case same
                            # as scalarInput.
                            fields.append(typ.fields[0].toJson())
                            totalSize += typ.fields[0].size
                            for field in typ.fields[1:]:
                                if field.offset + field.size <= minLen*lenType.bitSize//8:
                                    fields.append(field.toJson())
                                    totalSize += field.size
                        else:
                            for field in typ.fields:
                                if field.offset + field.size <= lenType.bitSize//8:
                                    fields.append(field.toJson())
                                    totalSize += field.size

                            if len(fields) == 0:
                                print(lenType.repr())
                                print("min: %d, max: %d" % (minLen, maxLen))
                                print(typ.repr())
                                raise Exception("unexpected struct and len")

                        if repeat:
                            if totalSize < minLen*lenType.bitSize//8:
                                # Add padding
                                buf = BufferType({"access": True, "data": [0xff]*(lenType.bitSize//8)}, 0)
                                if maxLen >= 1024:
                                    # Unlimited buffer
                                    arr = ArrayType({"field": buf.toJson(), "minLen": minLen-totalSize//(lenType.bitSize//8), \
                                        "maxLen": 0}, totalSize)
                                else:
                                    arr = ArrayType({"field": buf.toJson(), "minLen": minLen-totalSize//(lenType.bitSize//8), \
                                        "maxLen": maxLen-totalSize//(lenType.bitSize//8)}, totalSize)
                                fields.append(arr.toJson())

                            if all([each.equal(typ.fields[0]) for each in typ.fields[1:]]):
                                length = 0 if maxLen > 1024 else maxLen
                                return ArrayType({"field": fields[0], "size": typ.size, "minLen": minLen, \
                                    "maxLen": length}, typ.offset)

                            if len(fields) == 1:
                                typ = Type.construct(fields[0])
                            else:
                                typ = StructType({"fields": fields})
                        else:
                            if totalSize < lenType.bitSize//8:
                                buf = BufferType({"access": True, "data": [0xff]*(lenType.bitSize//8-totalSize)})
                                fields.append(buf.toJson())

                            length = 0 if maxLen > 1024 else maxLen
                            if len(fields) == 1:
                                typ = ArrayType({"field": fields[0], "size": typ.size, "minLen": minLen, \
                                    "maxLen": length}, typ.offset)
                            else:
                                new_struct = StructType({"fields": fields})
                                typ = ArrayType({"field": new_struct.toJson(), "size": typ.size, "minLen": minLen, \
                                    "maxLen": length}, typ.offset)
                    else:
                        # Normal struct or buffer, followed by an buffer with variable size.
                        # We can not trust both minLen and maxLen. MinLen can be smaller than expected,
                        # and maxLen is larger than expected.
                        fields = []
                        totalSize = 0
                        for i, field in enumerate(typ.fields):
                            if field.offset + field.size <= minLen*lenType.bitSize//8 or \
                                i != len(typ.fields)-1 or field.type != "buffer":
                                fields.append(field.toJson())
                                totalSize += field.size
                    
                        if totalSize < minLen*lenType.bitSize//8:
                            # Add padding
                            buf = BufferType({"access": True, "data": [0xff]}, 0)
                            arr = ArrayType({"field": buf.toJson(), "minLen": (minLen*lenType.bitSize//8-totalSize), \
                                "maxLen": maxLen*lenType.bitSize//8-totalSize}, totalSize)
                            fields.append(arr.toJson())
                        elif totalSize > minLen*lenType.bitSize//8:
                            # TODO:
                            if totalSize <= maxLen*lenType.bitSize//8:
                                # Add padding
                                buf = BufferType({"access": True, "data": [0xff]}, 0)
                                if maxLen >= 1024:
                                    # Unlimited buffer
                                    arr = ArrayType({"field": buf.toJson(), "minLen": 0, "maxLen": 0}, totalSize)
                                else:
                                    arr = ArrayType({"field": buf.toJson(), "minLen": 0, \
                                        "maxLen": maxLen*lenType.bitSize//8-totalSize}, totalSize)
                                fields.append(arr.toJson())
                            else:
                                print(lenType.repr())
                                print(typ.repr())
                                raise Exception("unexpected size")

                        if len(fields) == 1:
                            typ = Type.construct(fields[0])
                        typ = StructType({"fields": fields})
                # Syzkaller does not allow arbitrary string with a limited length
                # if typ.type == "string" and lenType.type in ["len", "range", "flag", "buffer", "const"]:
                #     pass
        if typ.type == "struct":
            typ.fields[0].access = True  # First field must be accessed.
            for i in range(len(typ.fields)):
                # If string is not the last field, we assume it has fixed length.
                if typ.fields[i].type == "string" and i != len(typ.fields)-1:
                    typ.fields[i].fixLen = typ.fields[i].size

        return typ

    ctx = Context()
    interface.refine_type(ctx, refine, isOffset=True)


def generateTemplate(serviceName, client, model, finalize=False):
    # resetAssignment(client.metaClass)
    sys_Open = ServiceOpen.create(serviceName, client)

    outfile = "%s_gen.txt" % client.metaClass
    f = open(outfile, "w")

    resources = dict()
    out_resources = dict()
    def search(ctx, typ):
        if typ.type == "resource":
            if ctx.dir&PtrType.DirOut:
                out_resources[typ.name] = typ

            if typ.name not in resources:
                resources[typ.name] = typ

    sys_Open.visit(Context(), search)
    for group, syscalls in model.methods.items():
        for syscall in syscalls:
            syscall.visit(Context(), search)
    for group, syscalls in model.async_methods.items():
        for syscall in syscalls:
            syscall.visit(Context(), search)

    for name, typ in resources.items():
        if name in out_resources:
            f.write("resource %s[%s]\n" % (name, typ.parent if typ.parent else Size2Type(typ.size)))
        else:
            # We use const instead of resource
            typename, definition = Const2Type(typ.getData(), typename=name)
            if definition is None:
                f.write("type %s %s\n" % (name, typename))
            else:
                f.write("%s\n" % definition)
    f.write("\n")

    # Simplify to ArrayType
    # def refine_array(ctx, typ):
    #     if typ.type == "struct":
    #         tgt = typ.fields[0]
    #         if all([each.equal(tgt) for each in typ.fields]):
    #             typ = ArrayType({"field": tgt.toJson(), "minLen": len(typ.fields), \
    #                 "maxLen": len(typ.fields), "size": typ.size}, typ.offset)
    #     return typ
    
    # for group, interfaces in model.methods.items():
    #     for interface in interfaces:
    #         interface.refine_type(Context(), refine_array)
    # for group, interfaces in model.async_methods.items():
    #     for interface in interfaces:
    #         interface.refine_type(Context(), refine_array)

    def write2file(fp, model):
        for group, interfaces in model.methods.items():
            for interface in interfaces:
                interface.generateTemplate(fp)
        for group, interfaces in model.async_methods.items():
            for interface in interfaces:
                interface.generateTemplate(fp)

    # At this point, fields may not have been assigned a name and thus we can not refine LenType.
    # We do generation before and after LenType refinement.
    with open(os.devnull, "w") as null:
        write2file(null, model)

    # Refine LenType
    for group, interfaces in model.methods.items():
        for interface in interfaces:
            # print("before:")
            # print(interface.repr())
            reduce_lenType(interface, finalize)
            reduce_struct(interface)
            # print("after:")
            # print(interface.repr())
    for group, interfaces in model.async_methods.items():
        for interface in interfaces:
            reduce_lenType(interface, finalize)
            reduce_struct(interface)

    sys_Open.generateTemplate(f)
    write2file(f, model)

    f.close()
    return outfile

def build_template(filename):
    syzkaller = getConfigKey("syzkaller")
    dstfile = os.path.join(syzkaller, "sys", "darwin", filename)
    os.replace(filename, dstfile)

    logger.debug("Rebuilding Syzkaller...")
    subprocess.run(["make"], check=True, cwd=syzkaller)

def generateInterface(service, client, dispatchTable, no_async=False, useLog=True, finalize=False):
    """Produce default template
    """
    print(client.metaClass)
    print(dispatchTable.repr())

    model = Model(dispatchTable.sym)
    port = ResourceType({"name": "%s_port" % client.metaClass, "parent": "io_connect_t", \
        "data": int2bytes(0, 8)}, typename="connection")

    for cmd, method in dispatchTable.methods.items():
        syscall = IOConnectCallMethod("%s_Group%d_0" % (client.metaClass, cmd))
        syscall.connection = port
        scalarInputCnt = method.getScalarInputCount()
        if scalarInputCnt not in (-1, 0xffffffff):
            syscall.inputCnt = Constant(scalarInputCnt, 4, "inputCnt")
            if scalarInputCnt:
                fields = []
                for i in range(scalarInputCnt):
                    fields.append(BufferOffset(8, i*8, None).toJson())
                if len(fields) == 1:
                    syscall.input = Pointer(fields[0], "input")
                else:
                    syscall.input = Pointer(StructType({"fields": fields}, offset=0).toJson(), "input")
            else:
                syscall.input = NullPointer(0, "input")
        structInputSize = method.getStructInputSize()
        if structInputSize not in (-1, 0xffffffff):
            syscall.inputStructCnt = Constant(structInputSize, 4, "inputStructCnt")
            if structInputSize:
                syscall.inputStruct = Pointer(Buffer(structInputSize, None).toJson(), "inputStruct")
            else:
                syscall.inputStruct = NullPointer(0, "inputStruct")

        scalarOutputCnt = method.getScalarOutputCount()
        if scalarOutputCnt not in (-1, 0xffffffff):
            if scalarOutputCnt:
                syscall.outputCnt = Pointer(Constant(scalarOutputCnt, 4, None).toJson(), "outputCnt")
                fields = []
                for i in range(scalarOutputCnt):
                    fields.append(BufferOffset(8, i*8, None).toJson())
                if len(fields) == 1:
                    syscall.output = Pointer(fields[0], "output")
                else:
                    syscall.output = Pointer(StructType({"fields": fields}).toJson(), "output")
                syscall.output.dir = PtrType.DirOut
            else:
                syscall.outputCnt = NullPointer(0, "outputCnt")
                syscall.output = NullPointer(0, "output")
        structOutputSize = method.getStructOutputSize()
        if structOutputSize not in (-1, 0xffffffff):
            if structOutputSize:
                syscall.outputStructCnt = Pointer(Constant(structOutputSize, 4, None).toJson(), "outputStructCnt")
                syscall.outputStruct = Pointer(Buffer(structOutputSize, None).toJson(), "outputStruct")
                syscall.outputStruct.dir = PtrType.DirOut
            else:
                syscall.outputStructCnt = NullPointer(0, "outputStructCnt")
                syscall.outputStruct = NullPointer(0, "outputStruct")

        syscall.validate()
        syscall.getCmdHandler(model.selector, cmd=cmd)
        if syscall.selector.type != "const":
            # default selector is 0
            syscall.selector = ConstType({"data": int2bytes(0, 4)}, typename="selector")
        # print("cmd: %d, %s" % (cmd, method.method))
        print(syscall.repr())
        if scalarInputCnt == 0 and structInputSize == 0:
            # No need for analysis
            syscall.status = 1
        # initally, each cmd corresponds to one syscall.
        model.methods[cmd] = [syscall]

    types = dict()
    testcases = os.path.join(TestCasePath, client.metaClass)
    if os.path.exists(testcases) and useLog:
        # If we have collected some traces, we could infer input structure from them.
        # Refine default model
        types = refine_model_with_log(testcases, model, client)

    for cmd, syscall in model.methods.items():
        # make a copy for async syscalls
        async_syscalls = []
        if not no_async:
            for each in syscall:
                reduce_struct(each)
                data = each.toJson()
                data["CallName"] = "syz_IOConnectCallAsyncMethod"
                async_syscalls.append(Syscall.load(data))
        model.async_methods[cmd] = async_syscalls

    dumps(os.path.join(ModelPath, client.metaClass), model)
    return generateTemplate(service.metaClass, client, model, finalize=finalize)


# Give a certain input, find the first output on which it depends.
def find_dependence(interfaces, index):
    itfCall = interfaces[index]

    ret = index
    # Check known dependence
    def get_resource(ctx, typ):
        if ctx.dir&PtrType.DirIn == 0:
            return

        if typ.type == "resource":
            # If this input has a dependence
            resource = typ.name
            data = typ.getData()
            # print("found input resource", resource, data)

            # Find the cloest ouput corresponding to the dependence
            last = index - 1
            while last >= 0:
                itf = interfaces[last]

                def find_resource(c, t):
                    if c.dir&PtrType.DirOut == 0:
                        return

                    if t.type == "resource" and t.name == resource and \
                        t.getData() == data:
                        c.ret = True
                        return True

                c = Context()
                itf.visit(c, find_resource)
                if c.ret:
                    break
                last -= 1

            if last != -1 and last < ctx.ret:
                # We may have multiple dependence, record the first one.
                ctx.ret = last
                # print("found output resource at ", last)

    ctx = Context()
    ctx.ret = index
    itfCall.visit(ctx, get_resource)

    return ret if ret < ctx.ret else ctx.ret

def get_testcase(interfaces, start, end):
    index = end
    while index >= start:
        # print(index, start, end)
        last = find_dependence(interfaces, index)
        if last != -1 and last < start:
            start = last
        index -= 1
    return start, end

def generateTestcases(logdir, model, serviceName, client):
    all_inputs = {}
    for name in os.listdir(logdir):
        if name.endswith(".log") and name.startswith("out_kernel_hook"):
            logger.debug("loading %s..." % name)
            syscalls = loads(os.path.join(logdir, name))
            refined = []
            for i, syscall in enumerate(syscalls):
                # print("parsing %d" % i)
                cmd = syscall.getCmdHandler(model.selector)
                test = syscall.copy()
                succeed = False
                for each in model.methods[cmd]:
                    try:
                        # print("before")
                        # print(test.repr())
                        test.simplify(each)
                        # print("after")
                        # print(test.repr())
                        refined.append(test)
                        succeed = True
                        break
                    except SimplifyError as e:
                        print(e)
                if not succeed:
                    print(syscall.repr())
                    print(model.methods[cmd][0].repr())
                    logger.error("Failed to simplify testcases")
            all_inputs[name] = refined

    path = os.path.join("workdir", "progs")
    shutil.rmtree(path, ignore_errors=True)
    try: os.mkdir(path)
    except: pass

    sysOpen = ServiceOpen.create(serviceName, client)
    sysClose = ServiceClose()

    num = 0
    for filename, inputs in all_inputs.items():
        print("parsing %s" % filename)
        if len(inputs) < 10:  # no need to split the testcase
            with open(os.path.join(path, "%d.prog" % num), "w") as f:
                port_num = inputs[-1].connection.getData()
                port = port_num if isinstance(port_num, list) else int2bytes(port_num, 8)
                sysOpen.port.ref.data = port
                sysClose.port.data = port
                json.dump(sysOpen.toArgs(), f)
                f.write("\n")
                for syscall in inputs:
                    syscall.connection.data = port
                    json.dump(syscall.toArgs(), f)
                    f.write("\n")
                json.dump(sysClose.toArgs(), f)
            num += 1
        else:
            last = len(inputs) - 1
            while last >= 0:
                start, end = get_testcase(inputs, last, last)
                logger.debug("find a testcase from %d to %d: %d" % (start, end, num))
                with open(os.path.join(path, "%d.prog" % num), "w") as f:
                    port_num = inputs[end].connection.getData()
                    port = port_num if isinstance(port_num, list) else int2bytes(port_num, 8)
                    sysOpen.port.ref.data = port
                    sysClose.port.data = port
                    json.dump(sysOpen.toArgs(), f)
                    f.write("\n")
                    for i in range(start, end+1):
                        # Note syscalls with different ports sometimes have dependence and thus we can not
                        # separate these calls by their ports. To reduce the number of calls, we use the
                        # same ports here.
                        inputs[i].connection.data = port
                        json.dump(inputs[i].toArgs(), f)
                        f.write("\n")
                    json.dump(sysClose.toArgs(), f)
                num += 1
                last = start - 1

    return os.path.abspath(path)

def generateConfig(client):
    item = {
        "target": "darwin/amd64",
        "http": "127.0.0.1:56741",
        "workdir": os.path.join(getConfigKey("syzkaller"), "workdir"),
        "sshkey": "/Users/CwT/.ssh/id_rsa",
        "ssh_user": getConfigKey("user") if client.access else "root",
        "syzkaller": getConfigKey("syzkaller"),
        "reproduce": False,
        "cover": False,
        "procs": 1,
        "type": "vmware",
        "vm": {
            "vmxpath": getConfigKey("vmpath"),
            "address": [
                getConfigKey("ip")
            ]
        }
    }

    enabled_syscalls = ["syz_IOServiceOpen$%s" % client.metaClass, "syz_IOServiceClose"]
    model = loads(os.path.join(ModelPath, client.metaClass))
    for group, syscalls in model.methods.items():
        for syscall in syscalls:
            enabled_syscalls.append(syscall.Name)
    for _, syscalls in model.async_methods.items():
        for syscall in syscalls:
            enabled_syscalls.append(syscall.Name)
    item["enable_syscalls"] = enabled_syscalls

    workdir = os.path.join(getConfigKey("syzkaller"), "workdir")
    if not os.path.exists(workdir):
        os.mkdir(workdir)

    cfg_path = os.path.join(workdir, "cfg_%s.json" % client.metaClass)
    logger.debug("generating config at %s" % cfg_path)
    with open(cfg_path, "w") as f:
        json.dump(item, f, indent=2)

    return 0
