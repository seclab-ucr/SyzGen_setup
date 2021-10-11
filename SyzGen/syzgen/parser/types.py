
import logging

logger = logging.getLogger(__name__)

#
#  Types for constructing structures
#

Constant = lambda val,size,name: ConstType({"data": int2bytes(val, size)}, typename=name)
ConstantOffset = lambda val,size,off,name: ConstType({"data": int2bytes(val, size)}, offset=off, typename=name)
Buffer = lambda size,name: BufferType({"data": [0xff]*size}, typename=name)
BufferOffset = lambda size,off,name: BufferType({"data": [0xff]*size}, offset=off, typename=name)
Pointer = lambda ref,name: PtrType({"ref": ref}, offset=0, typename=name)
PointerOffset = lambda ref,off,name: PtrType({"ref": ref}, offset=off, typename=name)
NullPointer = lambda off,name: ConstantOffset(0, 8, off, name)

class SimplifyError(Exception):
    """Testcase does not comply with given model"""
    pass

def int2bytes(value, size):
    ret = []
    for i in range(size):
        ret.append((value & 0xff))
        value = value >> 8
    return ret

def Size2Type(size):
    if size <= 1:
        return "int8"
    if size == 2:
        return "int16"
    if size == 4:
        return "int32"
    if size == 8:
        return "int64"
    return "array[int8, %d]" % size

def Const2Type(value, typename):
    size = len(value)
    types = {
        1: "const[0x%x, int8]",
        2: "const[0x%x, int16]",
        4: "const[0x%x, int32]",
        8: "const[0x%x, int64]"
    }
    if size in types:
        return types[size] % int.from_bytes(value, "little"), None

    definition = "%s {\n" % typename
    index = 0
    while len(value) > 0:
        size = len(value)
        if size >= 8: size = 8
        elif size >= 4: size = 4
        elif size >= 2: size = 2
        else: size = 1

        definition += "    field%d  %s\n" % (index, types[size] % int.from_bytes(value[:size], "little"))
        index += 1
        value = value[size:]
    definition += "} [packed]"
    return typename, definition

class Type(object):
    def __init__(self, type, offset=0, size=0, typename=None):
        self.type = type           # type name
        self.offset = offset
        self.size = size
        self.access = True
        self.typename = typename   # name of this field
        self.path = None           # path to another field
        self.isArray = False

    def visit(self, ctx, func, isOffset=False):
        return func(ctx, self)

    def refine_type(self, ctx, func, isOffset=False):
        return func(ctx, self)

    def refine(self, other):
        return self

    def resetName(self, prefix):
        if self.typename and self.typename.startswith(prefix):
            self.typename = None

    def repr(self, indent=0):
        ret = " "*indent + self.type + " " + str(self.size) + "\n"
        return ret

    def getTypeName(self, syscall):
        if self.typename is None:
            self.typename = syscall.assignNewName(self.type)
        return self.typename

    def equal(self, other):
        raise Exception("Not implemented")

    @staticmethod
    def construct(data, offset=0, isPtr=True):
        if "offset" in data:  # it is a pre-loaded model
            offset = data["offset"]
        type = data["type"]
        typename = data["typename"] if "typename" in data else None
        if type == "none":
            return None
        if type == "ptr" or (isPtr and "ptr" in data):
            return PtrType(data, offset, typename=typename)
        if type == "buffer":
            return BufferType(data, offset, typename=typename)
        if type == "resource":
            return ResourceType(data, offset, typename=typename)
        if type == "struct":
            return StructType(data, offset, typename=typename)
        if type == "const":
            return ConstType(data, offset, typename=typename)
        if type == "range":
            return RangeType(data, offset, typename=typename)
        if type == "flag":
            return FlagType(data, offset, typename=typename)
        if type == "string":
            return StringType(data, offset, typename=typename)
        if type == "array":
            return ArrayType(data, offset, typename=typename)
        if type == "len":
            return LenType(data, offset, typename=typename)
        raise Exception("unknown type %s" % type)

    def getData(self):
        return None

    def toJson(self):
        ret = {
            "type": self.type,
            "offset": self.offset,
            "size": self.size,
            "typename": self.typename
        }
        return ret

class PtrType(Type):
    DirIn = 1
    DirOut = 2
    DirInOut = 3

    def __init__(self, data, offset=0, typename=None):
        super(PtrType, self).__init__("ptr", offset=offset, size=8, typename=typename)
        self.data = None
        self.dir = 0 if "dir" not in data else data["dir"]

        if "ref" in data:
            self.ref = Type.construct(data["ref"], 0, isPtr=False)
        elif data["type"] == "ptr":
            # A pointer type without ref
            self.ref = None
        else:
            self.ref = Type.construct(data, 0, isPtr=False)
            self.data = data["ptr"]

        if "optional" in data:
            self.optional = data["optional"]
        else:
            self.optional = False

    def equal(self, other):
        if other.type == "ptr":
            if self.ref and other.ref and self.ref.equal(other.ref):
                return True
        return False

    def refine(self, other):
        if other.type == "struct":
            raise Exception("incorrect struct type")
        if other.type != "ptr":
            ret = other.refine(self)
            ret.typename = self.typename or ret.typename
            return ret
            # if other.size < self.size or len(other.fields) <= 1:
            #     raise Exception("incorrect struct type")
            # other = other.fields[0]  # due to alignment, the size must be larger than 8
            # return self.refine(other)
        # refine reference
        if self.ref is not None:
            self.ref = self.ref.refine(other.ref)
        return self

    def simplify(self, model):
        if model.type == "ptr":
            if self.ref is not None:
                self.ref = self.ref.simplify(model.ref)
            return self
        if model.type == "buffer" or model.type == "resource":
            if model.size != self.size:
                raise Exception("simplify ptr with wrong size")
            ret = model.toJson()
            ret["data"] = self.getData()
            return Type.construct(ret, offset=self.offset)

        # ERROR
        print("self", self.repr())
        print("model", model.repr())
        raise Exception("simplify ptr with struct")

    def visit(self, ctx, func, isOffset=False):
        if func(ctx, self):
            return True  # stop
        if self.ref:
            old_dir = ctx.dir
            ctx.dir = self.dir if self.dir else ctx.dir  # change the dir only if it is specified.
            ctx.parent = self
            ctx.path.append(0)
            ret = self.ref.visit(ctx, func, isOffset=isOffset)
            ctx.path.pop()
            ctx.parent = None
            ctx.dir = old_dir
            return ret

    def refine_type(self, ctx, func, isOffset=False):
        old_parent = ctx.parent  # We must save the parent as callback is invoked at last
        old_dir = ctx.dir
        if self.ref:
            ctx.path.append(0)
            ctx.parent = self
            ctx.dir = self.dir if self.dir else ctx.dir
            typename = self.ref.typename
            ret = self.ref.refine_type(ctx, func, isOffset=isOffset)
            if isinstance(ret, Type):
                self.ref = ret
            elif isinstance(ret, list):
                fields = [each.toJson() for each in ret]
                self.ref = StructType({"fields": fields}, offset=0, typename=typename)
            else:
                raise Exception("unknown type %s" % type(ret))
            ctx.path.pop()
        
        ctx.parent, ctx.dir = old_parent, old_dir
        return func(ctx, self)

    def resetName(self, prefix):
        super(PtrType, self).resetName(prefix)
        if self.ref:
            self.ref.resetName(prefix)

    def generateTemplate(self, syscall, dir, f, top=False):
        dir = self.dir if self.dir else dir
        typ, _ = self.ref.generateTemplate(syscall, dir, f, top=False)
        dir = "out" if self.dir&PtrType.DirOut else "in"
        if self.optional:
            unionName = syscall.assignNewName("union")
            definition = "%s [\n" % unionName
            definition += "    %s  const[0, intptr]\n" % syscall.assignNewName("field")
            definition += "    %s  %s\n" % (syscall.assignNewName("field"), typ)
            definition += "] [varlen]"
            f.write(definition + "\n")
            typ = "ptr[%s, %s]" % (dir, unionName)
        else:
            typ = "ptr[%s, %s]" % (dir, typ)

        return typ, self.getTypeName(syscall)

    def getData(self):
        if self.data:
            return int2bytes(self.data, 8)
        return int2bytes(0, 8)

    def repr(self, indent=0):
        ret = " "*indent + self.type + " " + str(self.size)
        if self.optional:
            ret += " optional"
        ret += "\n"
        if self.ref:
            ret += self.ref.repr(indent+2)
        return ret

    def toJson(self):
        ret = super(PtrType, self).toJson()
        ret["optional"] = self.optional
        ret["dir"] = self.dir
        if self.ref:
            ret["ref"] = self.ref.toJson()
        return ret


class BufferType(Type):
    def __init__(self, data, offset=0, typename=None):
        super(BufferType, self).__init__("buffer", offset=offset, size=len(data["data"]), typename=typename)
        self.data = data["data"]
        if "access" in data:
            self.access = data["access"]
        # Attributes for LenType
        self.path = None if "path" not in data else data["path"]
        self.bitSize = 8 if "bitSize" not in data else data["bitSize"]

    def equal(self, other):
        if other.type == "buffer":
            if self.size == other.size and self.path == other.path and self.bitSize == other.bitSize:
                return True
        return False

    def refine(self, other):
        # pointer can be optional
        if other.type == "ptr":
            if self.isNull():
                other.optional = True
            return other
            # else:
            #     print(self.data)

        # Prefer more fine-grained type
        if other.type == "struct":
            if self.path:
                # Len should be considered as a whole.
                # we probably only want one field
                data = other.fields[0].toJson()
                data["size"] = self.size
                data["data"] = int2bytes(int.from_bytes(data["data"], "little"), self.size)
                data["path"] = self.path
                data["bitSize"] = self.bitSize
                return Type.construct(data, self.offset)
            else:
                new_type = StructType({"fields": [self.toJson()]}, 0)
                return new_type.refine(other)

        if other.type in ["const", "resource", "flag", "range", "string"]:
            if self.path:
                other.path = self.path
                other.bitSize = self.bitSize
            return other

        if other.type != "buffer":
            raise Exception("Unknown type: %s" % other.type)

        # mark access flag
        if not other.access:
            self.access = False

        # Expand or split it to struct
        # FIXME: should we reserve other attributes
        if self.size < other.size:
            field1 = BufferType({"data": self.data})
            field2 = BufferType({"data": other.data[self.size:]}, self.size)
            return StructType({"fields": [field1.toJson(), field2.toJson()]})
        # elif self.size > other.size:
        #     field1 = BufferType({"data": self.data[:other.size]})
        #     field2 = BufferType({"data": self.data[other.size:]}, other.size)
        #     return StructType({"fields": [field1.toJson(), field2.toJson()]})

        return self

    def simplify(self, model):
        if model.type == "ptr":
            if int.from_bytes(self.getData(), "little") != 0:
                raise SimplifyError("Cannot simplify buffer to pointer")
            return ConstantOffset(0, self.size, self.offset, self.typename)

        if model.type == "const" and int.from_bytes(self.getRawData(), "little") != model.getData():
            raise SimplifyError("Cannot simplify buffer to const")
        if model.type == "range" and not model.min <= int.from_bytes(self.getRawData(), "little") <= model.max:
            raise SimplifyError("Cannot simplify buffer to range")
        if model.type == "flag" and int.from_bytes(self.getRawData(), "little") not in model.values:
            raise SimplifyError("Cannot simplify buffer to flag")

        if model.type == "struct":
            new_type = StructType({"fields": [self.toJson()]}, self.offset)
            return new_type.simplify(model)
        if model.type != "buffer":
            # Be consistent with more fine-grained type
            ret = model.toJson()
            ret["data"] = self.data[:model.size]
            return Type.construct(ret, self.offset)

        self.data = self.data[:model.size]
        self.size = len(self.data)
        return self

    def generateTemplate(self, syscall, dir, f, top=False):
        name = self.getTypeName(syscall)
        if self.size == 0:
            return "array[int8]", name
        if not self.access:
            if self.size in [1, 2, 4, 8]:
                return "const[0, %s]" % Size2Type(self.size), name
            return "array[const[0, int8], %d]" % self.size, name
        return Size2Type(self.size), name

    def isNull(self):
        if len(self.data) != 8:
            return False
        for each in self.data:
            if each != 0:
                return False
        return True

    def getData(self):
        '''
        This function can be overrided as opposed to getRawData
        '''
        return self.data

    def getRawData(self):
        return self.data

    def repr(self, indent=0):
        ret = " "*indent + self.type + ("+" if self.access else "-") + \
            " " + str(self.size) + " "
        data = self.getData()
        if isinstance(data, list):
            if len(data) <= 128:
                ret += str(self.getData())
            else:
                int2str = lambda x: str(x)
                ret += "["
                ret += (", ".join(map(int2str, data[:16])) + " ... " + ", ".join(map(int2str, data[-16:])))
                ret += "]"
        else:
            ret += str(data)
        if self.path:
            ret += " Sizeof %s with bitSize %d" % (str(self.path), self.bitSize)
        ret += "\n"
        return ret

    def toJson(self):
        ret = super(BufferType, self).toJson()
        ret["data"] = self.data
        ret["access"] = self.access
        if self.path:
            ret["path"] = self.path
            ret["bitSize"] = self.bitSize # if hasattr(self, "bitSize") else 8
        return ret

class LenType(Type):
    '''
    LenType is only used when generating templates, it is not persistent, meaning
    no field is stored as LenType. Instead, we use other types with attribute 'path'.
    '''
    def __init__(self, data, offset=0, typename=None):
        super(LenType, self).__init__("len", offset=offset, size=data["size"], typename=typename)
        self.lenField = data["lenField"]
        self.bitSize = data["bitSize"]
        self.max = data["max"]
        self.min = data["min"]

    def equal(self, other):
        if other.type == "len":
            if self.lenField == other.lenField and self.bitSize == other.bitSize:
                return True
        return False

    def generateTemplate(self, syscall, dir, f, top=False):
        prefix = "len"
        if self.bitSize in [16, 32, 64]:
            prefix = "bytesize%d" % (self.bitSize//8)
        elif self.bitSize == 1:
            prefix = "bitsize"
        # Note: For bitSize of 8 and others, we could directly use lenType because we would convert struct
        # into array.
        # elif self.bitSize != 8:
        #     raise Exception("bitSize of %d" % self.bitSize)

        # if self.max == 0:
        #     return "const[0]" if top else "const[0, %s]" % Size2Type(self.size), self.getTypeName(syscall)

        if top:
            return "%s[%s]" % (prefix, self.lenField), self.getTypeName(syscall)
        return "%s[%s, %s]" % (prefix, self.lenField, Size2Type(self.size)), self.getTypeName(syscall)

    def repr(self, indent=0):
        ret = " "*indent + self.type + " " + str(self.size) + " "
        ret += " Sizeof %s with bitSize %d [%d:%d]" % (str(self.path), self.bitSize, self.min, self.max)
        ret += "\n"
        return ret

    def toJson(self):
        ret = super(LenType, self).toJson()
        ret["lenField"] = self.lenField
        ret["bitSize"] = self.bitSize
        ret["max"] = self.max
        ret["min"] = self.min
        return ret

class ResourceType(BufferType):
    def __init__(self, data, offset=0, typename=None):
        super(ResourceType, self).__init__(data, offset, typename=typename)
        self.type = "resource"
        self.name = data["name"] if "name" in data else None
        self.parent = data["parent"] if "parent" in data else None

    def equal(self, other):
        if other.type == "resource":
            if self.name == other.name and self.parent == other.parent:
                return True
        return False

    def repr(self, indent=0):
        ret = " "*indent + self.type + " " + str(self.offset) + " " + str(self.size) + \
            " " + (" " if self.name is None else self.name) + "\n"
        return ret

    def refine(self, other):
        return self

    def toJson(self):
        ret = super(ResourceType, self).toJson()
        if self.name:
            ret["name"] = self.name
        if self.parent:
            ret["parent"] = self.parent
        return ret

    def generateTemplate(self, syscall, dir, f, top=False):
        return self.name, self.getTypeName(syscall)
        
class ConstType(BufferType):
    def __init__(self, data, offset=0, typename=None):
        super(ConstType, self).__init__(data, offset, typename=typename)
        self.type = "const"

    def equal(self, other):
        if other.type == "const":
            if self.size == other.size and self.getData() == other.getData():
                return True
        return False

    def generateTemplate(self, syscall, dir, f, top=False):
        if self.size <= 8:
            if top:
                return "const[%d]" % self.getData(), self.getTypeName(syscall)
            return "const[%d, %s]" % (self.getData(), Size2Type(self.size)), self.getTypeName(syscall)
        raise Exception("Not implemented yet")

    def refine(self, other):
        if other.type == "resource":
            return other

        if other.type == "const":
            if self.getData() != other.getData():  # Multiple constant values
                res = self.toJson()
                res["type"] = "flag"
                res["values"] = [self.getData(), other.getData()]
                return FlagType(res, offset=self.offset)
        elif other.type == "flag":
            return other.refine(self)

        return self

    def getData(self):
        raw_data = BufferType.getData(self)
        return int.from_bytes(raw_data, "little")

    def toJson(self):
        return super(ConstType, self).toJson()

class FlagType(ConstType):
    def __init__(self, data, offset=0, typename=None):
        super(FlagType, self).__init__(data, offset, typename=typename)
        self.type = "flag"
        self.values = set() if "values" not in data else set(data["values"])

    def equal(self, other):
        if other.type == "flag":
            if self.size == other.size and self.values == other.values:
                return True
        return False

    def toJson(self):
        ret = super(FlagType, self).toJson()
        ret["values"] = list(self.values)
        return ret

    def refine(self, other):
        if other.type == "resource":
            return other
        elif other.type == "const":
            self.values.add(other.getData())
        elif other.type == "flag":
            self.values = self.values.union(other.values)
        return self

    def generateTemplate(self, syscall, dir, f, top=False):
        typename = self.getTypeName(syscall)
        out = "%s = %s" % (typename, ", ".join([str(x) for x in self.values]))
        f.write(out + "\n")
        return "flags[%s, %s]" % (typename, Size2Type(self.size)), typename

    def repr(self, indent=0):
        ret = " "*indent + self.type + " " + str(self.size) + " " + str(list(self.values))
        if self.path:
            ret += " Sizeof %s" % str(self.path)
        ret += "\n"
        return ret

class StringType(FlagType):
    def __init__(self, data, offset=0, typename=None):
        super(StringType, self).__init__(data, offset, typename=typename)
        self.type = "string"
        self.fixLen = 0 if "fixLen" not in data else data["fixLen"]

    def equal(self, other):
        if other.type == "string":
            return True
        return False

    def refine(self, other):
        return self

    def toJson(self):
        ret = super(StringType, self).toJson()
        ret["fixLen"] = self.fixLen if hasattr(self, "fixLen") else 0
        return ret

    def generateTemplate(self, syscall, dir, f, top=False):
        typename = self.getTypeName(syscall)
        if len(self.values) > 1:
            out = "%s = %s" % (typename, ", ".join(["\"%s\"" % x for x in self.values]))
            f.write(out + "\n")
            if self.fixLen:
                return "string[%s, %d]" % (typename, self.fixLen), typename
            return "string[%s]" % typename, typename
        elif len(self.values) == 1:
            if self.fixLen:
                return "string[\"%s\", %d]" % (next(iter(self.values)), self.fixLen), typename
            return "string[\"%s\"]" % next(iter(self.values)), typename

        if self.fixLen:
            return "array[int8, %d]" % self.fixLen, typename
        return "string", typename

class RangeType(ConstType):
    def __init__(self, data, offset=0, typename=None):
        super(RangeType, self).__init__(data, offset, typename=typename)
        self.type = "range"
        self.min = data["min"]
        self.max = data["max"]
        self.stride = data["stride"]

    def equal(self, other):
        if other.type == "range":
            if self.size == other.size and self.min == other.min and \
                self.max == other.max and self.stride == other.stride:
                return True
        return False

    def toJson(self):
        ret = super(RangeType, self).toJson()
        ret["min"] = self.min
        ret["max"] = self.max
        ret["stride"] = self.stride
        return ret

    def refine(self, other):
        if other.type == "resource":
            return other
        return self

    def generateTemplate(self, syscall, dir, f, top=False):
        ret = ""
        if self.min == 0 and self.max == ((1<<self.size*8)-1):
            ret = "%s" % Size2Type(self.size)
        else:
            ret += "%s[%d:%d" % (Size2Type(self.size), self.min, min(self.max, self.min+(1<<64)-(1<<32)))
            if self.stride == 1:
                ret += "]"
            else:
                ret += (", %d]" % self.stride)
        return ret, self.getTypeName(syscall)

    def repr(self, indent=0):
        ret = " "*indent + self.type + " " + str(self.size)
        ret += " [%d:%d, %d]" % (self.min, self.max, self.stride)
        if self.path:
            ret += " Sizeof %s with bitSize %d" % (str(self.path), self.bitSize)
        ret += "\n"
        return ret

class StructType(Type):
    def __init__(self, data, offset=0, typename=None):
        super(StructType, self).__init__("struct", offset=offset, typename=typename)
        self.fields = []
        self.isArray = False if "isArray" not in data else data["isArray"]
        for each in data["fields"]:
            struct = Type.construct(each, offset, isPtr=True)
            self.fields.append(struct)
            offset += struct.size
            self.size += struct.size

    def equal(self, other):
        if other.type == "struct":
            if len(self.fields) == len(other.fields):
                for i in range(len(self.fields)):
                    if not self.fields[i].equal(other.fields[i]):
                        return False
                return True
        return False

    def split(self, index, size):
        field = self.fields[index]
        if field.type != "buffer":
            raise Exception("split none buffer type")

        rest = field.data[size:]
        field.data = field.data[:size]
        field.size = len(field.data)

        if len(rest) != 0:
            data = field.toJson()
            data["data"] = rest
            new_field = BufferType(data, field.offset+field.size)
            self.fields.insert(index+1, new_field)

    def merge(self, index, size):
        while True:
            if self.fields[index].size >= size:
                return
            if index+1 >= len(self.fields):
                raise Exception("no field to be merged")
            data = self.fields[index].toJson()
            data["data"] = self.fields[index].getRawData() + self.fields[index+1].getRawData()
            data["type"] = "buffer"
            new_field = BufferType(data, self.fields[index].offset)
            self.fields[index] = new_field
            del self.fields[index+1]

    def refine(self, other):
        if other.type == "buffer":
            other = StructType({"fields": [other.toJson()]}, 0)
        elif other.type != "struct":
            raise Exception("refine struct with %s" % other.type)

        fields = []
        l = r = 0
        while l < len(self.fields) and r < len(other.fields):
            ltype, rtype = self.fields[l], other.fields[r]
            if ltype.size == rtype.size:
                fields.append(ltype.refine(rtype))
            else:
                if ltype.size > rtype.size:
                    if ltype.type == "buffer":
                        self.split(l, rtype.size)
                    elif ltype.type == "resource": # non-separatable
                        other.merge(r, ltype.size)
                    else: # Not implemented yet
                        raise Exception("split type of %s" % ltype.type)
                else:
                    if rtype.type == "buffer":
                        other.split(r, ltype.size)
                    elif rtype.type == "resource":  # non-separatable
                        self.merge(l, rtype.size)
                    else:
                        raise Exception("split type of %s" % rtype.type)
                continue
            l += 1
            r += 1

        fields += self.fields[l:]

        self.fields = fields
        self.size = fields[-1].offset + fields[-1].size
        return self

    def simplify(self, model):
        others = []
        if model.type != "struct":
            others.append(model)
        else:
            others = model.fields

        fields = []
        l = r = 0
        while l < len(self.fields) and r < len(others):
            ltype, rtype = self.fields[l], others[r]
            if ltype.size == rtype.size:
                fields.append(ltype.simplify(rtype))
            else:
                if ltype.size > rtype.size:
                    self.split(l, rtype.size)
                else:
                    if l == len(self.fields) -1:
                        # if it is the last one, that's okay.
                        l += 1
                        r += 1
                        fields.append(ltype.simplify(rtype))
                        break

                    print(ltype.repr())
                    print(rtype.repr())
                    raise SimplifyError("ltype should has larger size")
                continue
            l += 1
            r += 1

        # Current testcase is shorter than our model, expand it but mark the rest as inaccessible.
        for i in range(r, len(others)):
            each = others[i].toJson()
            each["access"] = False
            fields.append(Type.construct(each))

        self.fields = fields
        self.size = fields[-1].offset + fields[-1].size
        if model.type != "struct":
            if len(self.fields) != 1:
                raise SimplifyError("Error when simplifying structure to other type")
            return self.fields[0]

        return self

    def visit(self, ctx, func, isOffset=False):
        if func(ctx, self):
            return True  # stop
        for i in range(len(self.fields)):
            if isOffset:
                ctx.path.append(self.fields[i].offset)
            else:
                ctx.path.append(i)
            ctx.parent = self
            ret = self.fields[i].visit(ctx, func, isOffset=isOffset)
            ctx.path.pop()
            ctx.parent = None
            if ret:
                return True  # stop

    def refine_type(self, ctx, func, isOffset=False):
        old_parent = ctx.parent
        fields = []
        for i in range(len(self.fields)):
            if isOffset:
                ctx.path.append(self.fields[i].offset)
            else:
                ctx.path.append(i)
            ctx.parent = self
            ret = self.fields[i].refine_type(ctx, func, isOffset=isOffset)
            if isinstance(ret, list):
                for field in ret:
                    fields.append(field)
            elif isinstance(ret, Type):
                fields.append(ret)
            else:
                raise Exception("unknown type %s" % type(ret))
            ctx.path.pop()

        offset = 0
        for field in fields:
            field.offset = offset
            offset += field.size

        self.fields = fields
        self.size = offset
        ctx.parent = old_parent
        return func(ctx, self)

    def resetName(self, prefix):
        super(StructType, self).resetName(prefix)
        for field in self.fields:
            field.resetName(prefix)

    def generateTemplate(self, syscall, dir, f, top=False):
        typename = self.getTypeName(syscall)
        definition = "%s {\n" % typename
        for i in range(len(self.fields)):
            typ, name = self.fields[i].generateTemplate(syscall, dir, f)
            definition += "    %s  %s\n" % (name, typ)
        definition += "} [packed]"
        f.write(definition + "\n")
        return typename, typename

    def repr(self, indent=0):
        ret = " "*indent + self.type + " " + str(self.size) + "\n"
        for each in self.fields:
            ret += each.repr(indent+2)
        return ret

    def toJson(self):
        ret = super(StructType, self).toJson()
        ret["fields"] = [each.toJson() for each in self.fields]
        ret["isArray"] = self.isArray if hasattr(self, "isArray") else False
        return ret

class ArrayType(Type):
    '''ArrayType is only used when generating templates'''
    def __init__(self, data, offset=0, typename=None):
        super(ArrayType, self).__init__("array", offset=offset, size=data["minLen"], typename=typename)
        self.ref = Type.construct(data["field"], 0)
        self.minLen = data["minLen"]
        self.maxLen = data["maxLen"]

    def equal(self, other):
        if other.type == "array":
            return self.ref.equal(other.ref)
        return False

    def generateTemplate(self, syscall, dir, f, top=False):
        subtype, _ = self.ref.generateTemplate(syscall, dir, f)
        minLen, maxLen = min(self.minLen, 4096), min(self.maxLen, 4096)
        if maxLen != 0:
            if minLen != maxLen:
                return "array[%s, %d:%d]" % (subtype, minLen, maxLen), self.getTypeName(syscall)
            return "array[%s, %d]" % (subtype, maxLen), self.getTypeName(syscall)
        return "array[%s]" % subtype, self.getTypeName(syscall)

    def toJson(self):
        ret = super(ArrayType, self).toJson()
        ret["field"] = self.ref.toJson()
        ret["minLen"] = self.minLen
        ret["maxLen"] = self.maxLen
        return ret

    def repr(self, indent=0):
        ret = " "*indent + self.type + " " + str(self.size)
        ret += " [%d:%d]\n" % (self.minLen, self.maxLen)
        return ret
