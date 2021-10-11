
import logging
import json
import os

from .types import ResourceType, Type, PtrType, BufferType, Constant

logger = logging.getLogger(__name__)

class Path(object):
    def __init__(self):
        self.path = []
        self.index = -1
        self.type = None

    def append(self, val):
        self.path.append(val)

    def pop(self):
        self.path.pop()

    def combine(self, path):
        if self.index != path.index:
            return None
        if not self.match(path.path):
            return None

        if self.type.offset+self.type.size == path.type.offset:
            new_path = Path()
            new_path.type = ResourceType({"data": self.type.getData() + path.type.getData()}, self.type.offset)
            new_path.path = list(self.path)
            new_path.index = self.index
            return new_path
        return None

    def overlap(self, path):
        # Path is superset of self
        if self.index != path.index:
            return False
        if not self.match(path.path):
            return False

        if path.type.offset <= self.type.offset and \
            self.type.offset+self.type.size <= path.type.offset+path.type.size:
            return True
        return False

    def match(self, path):
        if isinstance(path, list):
            if len(self.path) != len(path):
                return False
            for i in range(len(self.path)):
                if self.path[i] != path[i]:
                    return False
            return True

        if self.index != path.index:
            return False
        if len(self.path) != len(path.path):
            return False
        for i in range(len(self.path)):
            if self.path[i] != path.path[i]:
                return False
        if self.type.offset != path.type.offset:
            return False
        if self.type.size != path.type.size:
            return False
        return True

    def startswith(self, path):
        if isinstance(path, list):
            if len(self.path) < len(path):
                return False
            for i in range(len(path)):
                if self.path[i] != path[i]:
                    return False
            return True

        return False

    def equal(self, path):
        if not self.match(path):
            return False
        return self.type.getData() == path.type.getData()

    def getData(self):
        return self.type.getData()

    def repr(self):
        ret = "Path:\n"
        ret += "  path: " + str(self.path) + "\n"
        ret += "  index: " + str(self.index) + "\n"
        if self.type:
            ret += self.type.repr(indent=2)
        return ret

    def toJson(self):
        ret = {
            "path": self.path,
            "index": self.index
        }
        if self.type:
            ret["type"] = self.type.toJson()
        return ret

    @staticmethod
    def create(data):
        path = Path()
        path.index = data["index"]
        path.path = data["path"]
        if "type" in data:
            path.type = ResourceType(data["type"], data["type"]["offset"])
        return path

    def __hash__(self):
        return hash((str(self.path), self.index, self.type.offset, self.type.size))

    def __eq__(self, other):
        return self.match(other)

class Dependence(object):
    def __init__(self, outPath, inPath):
        self.outPath = outPath
        self.inPath = inPath

    def contained(self, dependences):
        for dependence in dependences:
            if self.match(dependence):
                return dependence
        return None

    def overlap(self, dependence):
        if not self.outPath.overlap(dependence.outPath):
            return False
        if not self.inPath.overlap(dependence.inPath):
            return False
        return True

    def match(self, dependence):
        if self.outPath.match(dependence.outPath) and \
            self.inPath.match(dependence.inPath):
            return True
        return False

    def combine(self, dependence):
        outP = self.outPath.combine(dependence.outPath)
        if outP is None:
            return None
        inP = self.inPath.combine(dependence.inPath)
        if inP is None:
            return None
        return Dependence(outP, inP)

    def repr(self):
        return "Out " + self.outPath.repr() + "\nIn " + self.inPath.repr() + "\n"

    def __hash__(self):
        return hash(self.outPath) + hash(self.inPath)

    def __eq__(self, other):
        return self.match(other)

class Context(object):
    def __init__(self):
        self.path = []
        self.arg = None
        self.ret = None
        self.parent = None
        self.dir = 0

def findLenByOffset(interface, path):
    def visit(ctx, typ):
        if isinstance(typ, BufferType) and typ.path == path:
            ctx.ret = (ctx.parent, typ)
            return True

    ctx = Context()
    ctx.ret = (None, None)
    interface.visit(ctx, visit)
    return ctx.ret

def findFieldByOffset(interface, path):
    def visit(ctx, typ):
        if path == ctx.path and typ.type == "ptr":
            ctx.ret = typ
            return True

    ctx = Context()
    ctx.ret = None
    interface.visit(ctx, visit, isOffset=True)
    return ctx.ret

def reduce_struct(syscall):
    """ For structure with only one field, we can reduce the struct to its field.
    """
    def simpify(ctx, typ):
        if typ.type == "struct" and len(typ.fields) == 1:
            typ.fields[0].typename = typ.typename
            return typ.fields[0]
        return typ

    ctx = Context()
    syscall.refine_type(ctx, simpify)

def refine_buffer(syscall):
    '''
    We initially assign a large byte array for any void pointer. After symbolic execution,
    we may refine the type and now let's eliminate irrelevant part from the structure based
    on the 'access' arritute that denotes whether we have accessed some particular field
    during the course.
    '''
    def refine(ctx, typ):
        if ctx.arg not in ["input", "inputStruct"]:
            return typ

        if typ.type == "struct":
            for i in range(len(typ.fields)-1, -1, -1):
                if typ.fields[i].access:
                    # the last accessible field
                    typ.fields = typ.fields[:i+1]
                    typ.size = typ.fields[i].offset + typ.fields[i].size
                    if len(typ.fields) == 1:
                        # reduce struct type if we only have field
                        typ.fields[0].typename = typ.typename
                        return typ.fields[0]
                    return typ

            # all are inaccessible, pick the first one
            typ.fields[0].access = True
            return typ.fields[0]
        elif typ.type == "ptr":
            # Note ref is refined before the ptr itself.
            # Ref only has one child which must be accessed.
            if typ.ref and not typ.ref.access:
                typ.ref.access = True

        return typ

    ctx = Context()
    syscall.refine_type(ctx, refine)

def reduce_length(syscall):
    """ For types with lenType, we reduce its size accordingly.
    """
    def refine(ctx, typ):
        if ctx.parent and ctx.parent.type == "ptr":
            _, lenType = findLenByOffset(syscall, ctx.path[:-1])
            if lenType:
                maximum = typ.size
                if lenType.type == "const":
                    maximum = lenType.getData()*lenType.bitSize//8
                elif lenType.type == "flag": # and typ.type == "buffer":
                    maximum = max(lenType.values)*lenType.bitSize//8
                elif lenType.type == "range": # and typ.type == "buffer":
                    # FIXME: add size constraints
                    maximum = min(lenType.max*lenType.bitSize//8, typ.size)

                if maximum > typ.size:
                    # Add padding
                    data = {"type": "buffer", "data": [0xff]*(maximum-typ.size)}
                    padding = BufferType(data, typ.size)
                    # print("add padding to:%s\n%s\n" % (interface.Name, ctx.parent.repr()))
                    # print(ctx.path)
                    if typ.type == "struct":
                        typ.fields.append(padding)
                        return typ
                    else:
                        return [typ, padding]
                elif maximum < typ.size:
                    # cut off
                    # print("cutting off buffer:%s\n%s\n" % (interface.Name, ctx.parent.repr()))
                    # print(ctx.path, maximum)
                    if maximum == 0:
                        return Constant(0, 0, None)

                    if typ.type == "buffer":
                        data = typ.toJson()
                        data["data"] = data["data"][:maximum]
                        return BufferType(data, typ.offset)
                    elif typ.type == "struct":
                        size = 0
                        for i in range(len(typ.fields)):
                            size += typ.fields[i].size
                            if size >= maximum:
                                typ.fields = typ.fields[:i+1]
                                typ.size = size
                                if len(typ.fields) == 1:
                                    return typ.fields[0]
                                return typ
                    elif typ.type == "string":
                        # For string, we only modify len.
                        return typ

                    print(typ.repr())
                    print(lenType.repr())
                    raise Exception("cutting off %s is not implemented!" % typ.type)

        return typ

    ctx = Context()
    syscall.refine_type(ctx, refine, isOffset=True)


def extractData(interface, path):
    def search_path(ctx, type):
        if path.match(ctx.path):
            ctx.ret = type.getData()[path.type.offset:path.type.offset+path.type.size]
            return True

    ctx = Context()
    interface.visit(ctx, search_path)
    return ctx.ret

def merge_dependences(model, all_logs, single_dependences):
    true_dependences = []
    # combine consecutive bytes
    visited = set()
    for group in single_dependences:
        queue = []
        for dep in single_dependences[group]:
            queue.append(dep)
            visited.add(dep)

        max_dependences = []
        while len(queue) > 0:
            c = queue.pop()
            found = False
            # We assume the dependence has length from 2~8
            if c.outPath.type.size < 8:
                for dep in single_dependences[group]:
                    new = c.combine(dep)
                    if new and new not in visited:
                        queue.append(new)
                        visited.add(new)
                        found = True
                        break
            if not found:
                if c.outPath.type.size >= 2:
                    # assume dependence has at least 2 bytes
                    max_dependences.append(c)

        # de-duplicate
        i = 0
        while i < len(max_dependences):
            found = False
            for j in range(len(max_dependences)):
                if j == i:
                    continue
                # Dependence j contains dependence i
                if max_dependences[i].overlap(max_dependences[j]):
                    found = True
                    break
            if found:
                del max_dependences[i]
            else:
                i += 1

        # Check if it is constant
        for dep in max_dependences:
            out_values = set()
            in_values = set()
            for _, ents in all_logs.items():
                # seprately analyze each log file
                for ent in ents:
                    if ent.getCmdHandler(model.selector) == dep.outPath.index:
                        data = extractData(ent, dep.outPath)
                        out_values.add(str(data))
                    if ent.getCmdHandler(model.selector) == dep.inPath.index:
                        data = extractData(ent, dep.inPath)
                        in_values.add(str(data))

            if len(in_values) >= 2 and len(out_values) >= 2:
                true_dependences.append(dep)

    for dep in true_dependences:
        print(dep.repr())
    return true_dependences

def infer_dependence_input(all_logs, model, target=None):
    potential_dependences = []
    for cmd, syscall in model.methods.items():
        if target is not None and cmd != target:
            continue

        syscall = syscall[0]
        # fixate the syscall that may produce dependence.
        if syscall.output.type != "ptr" and syscall.outputStruct.type != "ptr":
            # empty output can not contain dependence.
            continue

        logger.debug("collect all potential dependences")
        candidates = dict()
        for _, ents in all_logs.items():
            # separately analyze each log file
            resources = []
            for ent in ents:
                cur_cmd = ent.getCmdHandler(model.selector)
                if cur_cmd == cmd:
                    def search_output(ctx, typ):
                        # if ctx.dir&PtrType.DirOut == 0:
                        #     return
                        if ctx.arg not in ["output", "outputStruct"]:
                            return

                        if typ.type == "buffer" and typ.access:
                            data = typ.getData()
                            for i in range(min(typ.size, 64)): # maximum range to search
                                # Assume each byte could be a dependence value
                                resource = ResourceType({"data": data[i:i+1]}, i)
                                path = Path()
                                path.index = cmd
                                path.type = resource
                                path.path = list(ctx.path)
                                ctx.ret.append(path)

                    ctx = Context()
                    ctx.ret = []
                    ent.visit(ctx, search_output)
                    resources.append(ctx.ret)

                if ent.input.type == "ptr" or ent.inputStruct.type == "ptr":
                    def search_input(ctx, typ):
                        # if ctx.dir&PtrType.DirIn == 0:
                        #     return
                        # Avoid parsing data from outputStructCnt, outputCnt
                        if ctx.arg not in ["input", "inputStruct"]:
                            return

                        if typ.type == "buffer" and typ.access:
                            data = typ.getData()
                            for tmp in reversed(resources):
                                for path in tmp:
                                    tomatch = path.type.getData()[0]  # only has one byte
                                    offsets = [i for i in range(len(data)) if data[i] == tomatch]
                                    for offset in offsets:
                                        new_path = Path()
                                        new_path.type = ResourceType({"data": data[offset:offset+1]}, offset)
                                        new_path.path = list(ctx.path)
                                        new_path.index = cur_cmd
                                        new_dep = Dependence(path, new_path)
                                        # if not new_dep.contained(dependences):
                                        ctx.ret[new_dep] = new_dep

                    ctx = Context()
                    ctx.ret = dict()
                    ent.visit(ctx, search_input)
                    if cur_cmd not in candidates:
                        candidates[cur_cmd] = []
                    candidates[cur_cmd].append(ctx.ret)

        logger.debug("confirm single-byte dependences")
        single_dependences = {}
        # candidates: {
        # groupX: [
        #   1st call {dep: dep}
        #   2nd call {dep: dep}
        # ]
        # }
        for group, items in candidates.items():
            if len(items) == 0:
                continue

            hypothesis = items[0]
            for dependences in items[1:]:
                new_hypothesis = []
                for x in hypothesis:
                    if x in dependences:
                        new_hypothesis.append(x)
                hypothesis = new_hypothesis
                if len(hypothesis) == 0:
                    break

            single_dependences[group] = []
            for dep in hypothesis:
                single_dependences[group].append(dep)

        logger.debug("merge single-byte dependences")
        true_dependences = merge_dependences(model, all_logs, single_dependences)

        potential_dependences += true_dependences
        # if cmd == 0:
        #     from IPython import embed; embed()

    return potential_dependences

def infer_dependence_output(all_logs, model, target=None):
    potential_dependences = []
    for cmd, syscall in model.methods.items():
        if target is not None and cmd != target:
            continue

        syscall = syscall[0]
        # fixate the syscall that may produce dependence.
        if syscall.output.type != "ptr" and syscall.outputStruct.type != "ptr":
            # empty output can not contain dependence.
            continue

        logger.debug("collect all potential dependences for cmd %d" % cmd)
        candidates = list()
        resources = []
        total_resources = 0
        for _, ents in all_logs.items():
            # separately analyze each log file
            total_resources += len(resources)   # add previous resource number before we re-initialize it.
            resources = []
            for ent in ents:
                cur_cmd = ent.getCmdHandler(model.selector)
                if cur_cmd == cmd:
                    def search_output(ctx, typ):
                        # if ctx.dir&PtrType.DirOut == 0:
                        #     return
                        if ctx.arg not in ["output", "outputStruct"]:
                            return

                        if typ.type == "buffer" and typ.access:
                            data = typ.getData()
                            for i in range(min(typ.size, 64)): # maximum range to search
                                # Assume each byte could be a dependence value
                                resource = ResourceType({"data": data[i:i+1]}, i)
                                path = Path()
                                path.index = cmd
                                path.type = resource
                                path.path = list(ctx.path)
                                ctx.ret.append(path)

                    ctx = Context()
                    ctx.ret = []
                    ent.visit(ctx, search_output)
                    resources.append(ctx.ret)
                    candidates.append(dict())
                    # Assume one syscall can not consume its own output.
                    continue

                if ent.input.type == "ptr" or ent.inputStruct.type == "ptr":
                    def search_input(ctx, typ):
                        # if ctx.dir&PtrType.DirIn == 0:
                        #     return
                        # Avoid parsing data from outputStructCnt, outputCnt
                        if ctx.arg not in ["input", "inputStruct"]:
                            return

                        if typ.type == "buffer" and typ.access:
                            data = typ.getData()
                            for idx, tmp in enumerate(resources):
                                for path in tmp:  # each byte of the output
                                    tomatch = path.type.getData()[0]  # only has one byte
                                    offsets = [i for i in range(len(data)) if data[i] == tomatch]
                                    for offset in offsets:
                                        new_path = Path()
                                        new_path.type = ResourceType({"data": data[offset:offset+1]}, offset)
                                        new_path.path = list(ctx.path)
                                        new_path.index = cur_cmd
                                        new_dep = Dependence(path, new_path)
                                        candidates[idx+total_resources][new_dep] = new_dep
                                        # if not new_dep.contained(dependences):
                                        # ctx.ret[new_dep] = new_dep

                    ctx = Context()
                    ctx.ret = dict()
                    ent.visit(ctx, search_input)
                    # if cur_cmd not in candidates:
                    #     candidates[cur_cmd] = []
                    # candidates[cur_cmd].append(ctx.ret)
                    # logger.debug("found %d pairs" % len(ctx.ret))

        logger.debug("confirm single-byte dependences")
        single_dependences = {}
        if len(candidates) > 1:
            for dep in candidates[0]:
                found = True
                for x in candidates[1:]:
                    if dep not in x:
                        found = False
                        break
                if found:
                    if dep.inPath.index not in single_dependences:
                        single_dependences[dep.inPath.index] = list()
                    single_dependences[dep.inPath.index].append(dep)

        logger.debug("merge single-byte dependences groups: %d" % len(single_dependences))
        # if cmd == 0:
        #     from IPython import embed; embed()
        #     pass

        true_dependences = merge_dependences(model, all_logs, single_dependences)

        potential_dependences += true_dependences
        # if cmd == 0:
        #     from IPython import embed; embed()
        #     pass

    return potential_dependences

def infer_extra_dependence(all_inputs, model, filepath):
    """ Some dependence is just fixed constant like Bluetooth address. Users are allowed to
    provided external magic bytes as dependence.
    """
    if not os.path.exists(filepath):
        return []
    magic_bytes = []
    with open(filepath, "r") as fp:
        data = json.load(fp)
        for _, each in data.items():
            magic_bytes.append(bytes(each))
    if len(magic_bytes) == 0:
        return []

    candidates = {}
    for _, inputs in all_inputs.items():
        for inter in inputs:
            cmd = inter.getCmdHandler(model.selector)
            ctx = Context()
            dependences = {}
            def search(ctx, typ):
                if ctx.dir&PtrType.DirIn == 0:
                    return

                if typ.type == "buffer":
                    data = typ.getData()
                    for i, each in enumerate(magic_bytes):
                        idx = bytes(data).find(each)
                        if idx >= 0:
                            resource = ResourceType({"data": list(each)}, idx)
                            path = Path()
                            path.index = cmd
                            path.type = resource
                            path.path = list(ctx.path)
                            empty_path = Path()
                            empty_path.index = -(i+1) # used to distinguish different dependence
                            empty_path.type = ResourceType({"data": list(each)}, 0)
                            empty_path.path = []
                            new_dep = Dependence(empty_path, path)
                            dependences[new_dep] = new_dep

            inter.visit(ctx, search)
            if cmd not in candidates:
                candidates[cmd] = []
            candidates[cmd].append(dependences)

    logger.debug("finish collecting potential extra dependence")
    true_dependences = []
    for group, items in candidates.items():
        logger.debug("group: %d", group)
        if len(items) == 0:
            continue

        hypothesis = items[0]
        for dependences in items[1:]:
            new_hypothesis = []
            for x in hypothesis:
                if x in dependences:
                    new_hypothesis.append(x)
                    # logger.debug("add one hypothesis")
                    # print(x.repr())
            hypothesis = new_hypothesis
            if len(hypothesis) == 0:
                break

        for each in hypothesis:
            true_dependences.append(each)

    return true_dependences

def refine_dependence(model, dependences, types):
    '''
    For the dependence we found, we could further refine the structure by creating a 'resource'
    type for each dependence.
    '''
    for dep in dependences:
        print(dep.repr())

    for group, interface in model.methods.items():
        interface = interface[0]
        ctx = Context()
        relevant = [dep for dep in dependences if dep.inPath.index == group or dep.outPath.index == group]
        
        def refine(ctx, typ):
            if typ.type != "buffer" or typ.size == 0:  # empty buffer
                return typ

            found = False
            for dep in relevant:
                if dep.outPath and dep.outPath.match(ctx.path) and dep.outPath.index == group and \
                    typ.offset <= dep.outPath.type.offset < typ.offset+typ.size:
                    off = dep.outPath.type.offset - typ.offset
                    size = dep.outPath.type.size
                    found = True
                if dep.inPath and dep.inPath.match(ctx.path) and dep.inPath.index == group and \
                    typ.offset <= dep.inPath.type.offset < typ.offset+typ.size:
                    off = dep.inPath.type.offset - typ.offset
                    size = dep.inPath.type.size
                    found = True
                if found:
                    # split the buffer
                    fields = []
                    for i, (start, end) in enumerate([(0, off), (off, off+size), (off+size, typ.size)]):
                        if start == end:
                            continue
                        data = typ.toJson()
                        data["data"] = typ.data[start:end]
                        data["offset"] = start + typ.offset
                        data["typename"] = None # reset typename
                        if i == 1:
                            data["type"] = "resource"
                            data["name"] = types[dep.outPath]["name"]
                        fields.append(Type.construct(data))
                    if len(fields) == 1:
                        fields[0].typename = typ.typename
                        return fields[0]
                    return fields

            return typ

        interface.refine_type(ctx, refine)

def reduce_syscall(syscall1, syscall2):
    if syscall1.CallName != syscall2.CallName:
        return None, 0

    def reduce_argument(typ1, typ2, changes):
        msg = ""
        if typ1.type == "ptr" and typ2.type == "ptr":
            ref, changes, msg = reduce_argument(typ1.ref, typ2.ref, changes)
            if ref is None: return None, changes, msg
            typ1.ref = ref
        elif typ1.type == "struct" and typ2.type == "struct":
            fields = []
            for i in range(min(len(typ1.fields), len(typ2.fields))):
                field1 = typ1.fields[i]
                field2 = typ2.fields[i]
                if field1.size != field2.size:
                    return None, changes, "fields have different sizes %d and %d" % (field1.size, field2.size)
                field, changes, msg = reduce_argument(field1, field2, changes)
                if field is None: return None, changes, msg
                fields.append(field)
            # TODO: change merge of len 
            if len(fields) < len(typ1.fields):
                fields.extend(typ1.fields[len(fields):])
                changes += 1
            if len(fields) < len(typ2.fields):
                fields.extend(typ2.fields[len(fields):])
                changes += 1
            typ1.fields = fields
        else:
            if typ1.type != typ2.type:
                def merge_ptr_const(ptr, const):
                    # Pointers can have a special value 0.
                    if ptr.type == "ptr" and const.type == "const" and const.getData() == 0:
                        return True, ptr, "merge ptr and null"
                    return False, None, ""

                def merge_const_flag(const, flag):
                    if const.type == "const" and flag.type == "flag":
                        flag.values.add(const.getData())
                        return True, flag, "merge const and flag"
                    return False, None, ""

                def merge_flag_range(flag, range):
                    if flag.type == "flag" and range.type == "range":
                        # flag is included in the range
                        if all([range.min <= val <= range.max for val in flag.values]):
                            return True, range, "merge flag and range"
                        # flag expands range
                        cmin, cmax = range.min, range.max
                        while cmax+1 in flag.values:
                            cmax += 1
                        while cmin-1 in flag.values:
                            cmin -= 1
                        if all([cmin <= val <= cmax for val in flag.values]):
                            range.min, range.max = cmin, cmax
                            return True, range, "merge flag and range"

                    return False, None, ""

                def merge_const_range(const, range):
                    if const.type == "const" and range.type == "range":
                        if range.min <= const.getData() <= range.max:
                            return True, range, "merge const and range"
                        if const.getData() == range.min-1:
                            range.min -= 1
                            return True, range, "merge const and range"
                        if const.getData() == range.max+1:
                            range.max += 1
                            return True, range, "merge const and range"
                    return False, None, ""

                merge_func = [merge_ptr_const, merge_const_flag, merge_flag_range, merge_const_range]
                for a, b in [(typ1, typ2), (typ2, typ1)]:
                    for func in merge_func:
                        succeed, typ, msg = func(a, b)
                        if succeed:
                            if a.path and a.path == b.path:
                                # Special case where we can merge len fields without counting it as a change.
                                return typ, changes, msg
                            return typ, changes+1, msg

                return None, changes, "different types between %s and %s" % (typ1.type, typ2.type)
            else:
                if typ1.size != typ2.size:
                    return None, changes, "different size of %s" % typ1.type
                if typ1.type == "const" and typ1.getData() != typ2.getData():
                    # merge two consts to flag
                    changes += 1
                    data = typ1.toJson()
                    data["values"] = [typ1.getData(), typ2.getData()]
                    data["type"] = "flag"
                    return Type.construct(data), changes, "merge consts"
                if typ1.type == "range" and (typ1.min != typ2.min or typ1.max != typ2.max):
                    # merge consecutive ranges
                    if typ1.min <= typ2.max+1 and typ2.min <= typ1.max+1 and typ1.stride == typ2.stride:
                        typ1.min = min(typ1.min, typ2.min)
                        typ1.max = max(typ1.max, typ2.max)
                        changes += 1
                        return typ1, changes, "merge ranges"
                    return None, changes, "merge ranges failed"
                if typ1.type == "flag" and typ1.values != typ2.values:
                    changes += 1
                    typ1.values.update(typ2.values)
                    return typ1, changes, "merge flags"
        return typ1, changes, msg

    base = syscall1.copy()
    target = syscall2.copy()
    base.numOfBB = max(base.numOfBB, target.numOfBB)

    changes = 0
    for i in range(len(base.args)):
        arg, changes, msg = reduce_argument(base.args[i], target.args[i], changes)
        if msg:
            print(msg)
        if arg is None or changes > 1:
            return None, changes
        base.args[i] = arg
    base.validate()
    return base, changes

def existSyscall(sys, calls):
    for each in calls:
        if sys.equal(each):
            return True
    return False

def reduce_syscalls_preprocess(syscalls):
    ret = []
    merged = set()
    for i in range(len(syscalls)):
        if i in merged:
            continue
        if existSyscall(syscalls[i], syscalls[i+1:]):
            continue
            
        found = False
        for j in range(i+1, len(syscalls)):
            new_syscall, num = reduce_syscall(syscalls[i], syscalls[j])
            if new_syscall:
                if existSyscall(new_syscall, syscalls[i:i+1]):
                    merged.add(j)
                elif existSyscall(new_syscall, syscalls[j:j+1]):
                    found = True
                    break
        if not found:
            ret.append(syscalls[i])
    print("reduce_syscalls_preprocess from %d to %d" % (len(syscalls), len(ret)))
    return ret

def reduce_syscalls_fast(syscalls):
    print("reduce_syscalls_fast", len(syscalls))
    
    changed = True
    while changed:
        changed = False
        tmp = []
        merged = set()
        for i in range(len(syscalls)):
            if i in merged:
                continue
            for j in range(i+1, len(syscalls)):
                if j in merged:
                    continue
                new_syscall, num = reduce_syscall(syscalls[i], syscalls[j])
                if new_syscall and not existSyscall(new_syscall, tmp):
                    print("merge", i, j)
                    tmp.append(new_syscall)
                    merged.add(i)
                    merged.add(j)
                    changed = True
            if i not in merged:
                merged.add(i)
                if not existSyscall(syscalls[i], tmp):
                    tmp.append(syscalls[i])
        syscalls = tmp
    return syscalls

def reduce_syscalls(syscalls):    
    syscalls = reduce_syscalls_preprocess(syscalls)
    if len(syscalls) > 64:
        return reduce_syscalls_fast(syscalls)
    
    changed = True
    while changed:
        changed = False
        tmp = []
        merged = set()
        # Check every pair
        for i in range(len(syscalls)):
            for j in range(i+1, len(syscalls)):
                new_syscall, num = reduce_syscall(syscalls[i], syscalls[j])
                if new_syscall and not existSyscall(new_syscall, tmp):
                    print("merge", i, j)
                    tmp.append(new_syscall)
                    merged.add(i)
                    merged.add(j)
                    changed = True
            if i not in merged:
                merged.add(i)
                if not existSyscall(syscalls[i], tmp):
                    tmp.append(syscalls[i])
        if len(tmp) > len(syscalls)*2:
            return reduce_syscalls_fast(syscalls)
        syscalls = tmp
            
    return syscalls
