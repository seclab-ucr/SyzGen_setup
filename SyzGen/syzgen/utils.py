
import subprocess
import os
import re
import json
import logging
import pickle
import sys

from claripy.ast.base import Base
from claripy import operations
from claripy.ast.bv import Extract, Reverse
from collections import defaultdict
from functools import lru_cache

logger = logging.getLogger(__name__)
sys.setrecursionlimit(3000)  # for extractFields

CONFIG_PATH = "config"
TMP_PATTERN = re.compile(r"^tmp_([\da-f]+)_")

def dumps(path, obj):
    with open(path, "wb") as fp:
        pickle.dump(obj, fp)

def loads(path, default=None):
    if not os.path.exists(path):
        return default
        
    with open(path, "rb") as fp:
        return pickle.load(fp)

@lru_cache(maxsize=None)
def loadConfig():
    with open(CONFIG_PATH, "r") as fp:
        return json.load(fp)

def getRemoteAddr():
    config = loadConfig()
    remote_addr = "%s@%s" % (config["user"], config["ip"])
    return remote_addr

def copy2vm(filepath):
    remote_addr = getRemoteAddr()
    subprocess.run(["scp", filepath, "%s:./" % remote_addr], check=True)

def getConfigKey(key, default=None):
    config = loadConfig()
    if key not in config:
        if default is None:
            raise Exception("Can not find key %s in the config file" % key)
        return default
    return config[key]

def vmrun(cmd="reset", disable_gui=True):
    if cmd not in ("reset", "start", "stop"):
        raise Exception("wrong argument!")
    config = loadConfig()
    vmpath = config["vmpath"]
    logger.debug("vmrun %s %s" % (cmd, vmpath))
    extra_args = []
    if cmd in ["reset", "stop"]:
        extra_args.append("hard")    # hard or soft
    if cmd == "start" and disable_gui:
        extra_args.append("nogui")
    subprocess.run(["vmrun", cmd, vmpath, *extra_args], check=True)

def isVmRunning():
    vmpath = getConfigKey("vmpath")
    ret = subprocess.run(["vmrun", "list"], stdout=subprocess.PIPE, check=True)
    return vmpath in str(ret.stdout)

def check_output(cmds, runInVM=False):
    if not runInVM:
        ret = subprocess.run(cmds, check=True, cwd=os.getcwd(), stdout=subprocess.PIPE)
    else:
        remote_addr = getRemoteAddr()
        cmds = ["ssh", remote_addr, " ".join(cmds)]
        ret = subprocess.run(cmds, check=True, cwd=os.getcwd(), stdout=subprocess.PIPE)
    return ret.stdout

def check_stderr(cmds, runInVM=False):
    if not runInVM:
        ret = subprocess.run(cmds, cwd=os.getcwd(), stderr=subprocess.PIPE)
    else:
        remote_addr = getRemoteAddr()
        cmds = ["ssh", remote_addr, " ".join(cmds)]
        ret = subprocess.run(cmds, cwd=os.getcwd(), stderr=subprocess.PIPE)
    return ret.stderr

def check_retval(cmds, runInVM=False, timeout=None):
    if not runInVM:
        ret = subprocess.run(cmds, cwd=os.getcwd())
    else:
        remote_addr = getRemoteAddr()
        cmds = ["ssh", remote_addr, " ".join(cmds)]
        ret = subprocess.run(cmds, timeout=timeout, cwd=os.getcwd())
    return ret.returncode

def demangle(name):
    # https://github.com/nico/demumble
    output = check_output(["./libs/demumble", name])
    return output.decode().strip()

def checkVM():
    # testService
    if check_retval(["ls", "testService"], runInVM=True):
        if not os.path.exists("./libs/testService"):
            raise Exception("please build libs/testService first")
        copy2vm("./libs/testService")
    # registry
    if check_retval(["ls", "registry"], runInVM=True):
        copy2vm("./libs/registry")

def addEntitlement(filepath):
    # Give entitlement
    cmds = ["sh", "./autosign.sh", filepath]
    logger.debug("%s (%s)" % (" ".join(cmds), os.path.join(os.getcwd(), "libs")))
    subprocess.run(cmds, check=True, cwd=os.path.join(os.getcwd(), "libs"))

def extractFields(expr, data, depth=0):
    if depth > 2000:
        # make sure it does not exceed the recursion limit.
        return

    if expr.op == 'Extract' and expr.args[2].op == 'BVS':
        # Note the endian
        data.add((expr.args[-1]._encoded_name, expr.args[0], expr.args[1]))
        return
    
    if expr.op == 'Reverse' and expr.args[0].op == "Concat":
        # <BV64 0x0 .. structInput_38_928[7:0] .. structInput_38_928[15:8] .. structInput_38_928[23:16] .. structInput_38_928[31:24]>
        body = expr.args[0]
        new_args = [ele for ele in reversed(body.args)]
        new_expr = body.make_like(body.op, new_args, simplify=True)
        extractFields(new_expr, data, depth+1)
        return
    
    if expr.op == 'BVS':
        data.add((expr._encoded_name, expr.length-1, 0))
        return
    
    for each in expr.args:
        if isinstance(each, Base):
            extractFields(each, data, depth+1)

def extractField(expr):
    # e.g., Reverse(structInput_2_928[479:416])
    if expr.op == 'Extract' and expr.args[2].op == 'BVS':
        return expr.args[2]._encoded_name, expr.args[0], expr.args[1]
    if expr.op == 'Reverse':
        return extractField(expr.args[0])
    if expr.op == 'BVS':
        return expr._encoded_name, expr.length-1, 0
    return None, 0, 0

def extractName(name):
    if type(name) is bytes:
        name = name.decode()
    m = re.search(r'(.+)_[\d]+_[\d]', name)
    if m:
        return m.group(1)
    return None

def extractSymbols(expr, data, excludes=[]):
    if expr.op == 'Extract' and expr.args[2].op == 'BVS':
        for each in excludes:
            if expr.args[2].args[0].startswith(each):
                return
        # Note the endian
        for i, ele in enumerate(data[expr.args[-1]]):
            if ele[1] <= expr.args[0]+1 and expr.args[1] <= ele[0]+1:
                data[expr.args[-1]][i] = [max(ele[0], expr.args[0]), min(ele[1], expr.args[1])]
                return
        data[expr.args[-1]].append([expr.args[0], expr.args[1]])
        return
    
    if expr.op == 'BVS':
        for each in excludes:
            if expr.args[0].startswith(each):
                return
        data[expr] = []
        data[expr].append([expr.length-1, 0])
        return
    
    for each in expr.args:
        if isinstance(each, Base):
            extractSymbols(each, data, excludes=excludes)

def extractSymbol(expr):
    symbols = defaultdict(list)
    extractSymbols(expr, symbols)
    if len(symbols) > 1: return None, 0, 0
    for sym, arr in symbols.items():
        if len(arr) > 1: return None, 0, 0
        for l, r in arr:
            return sym, l, r
    return None, 0, 0

def extractVariables(expr):
    symbols = defaultdict(list)
    if isinstance(expr, list):
        for each in expr:
            extractSymbols(each, symbols)
    else:
        extractSymbols(expr, symbols)
    
    cmds = []
    for sym, arr in symbols.items():
        for left, right in arr:
            cmds.append(Extract(left, right, sym))
    return cmds

def extractBaseOffset(state, expr):
    if expr.op != '__add__':
        return None, None

    # It must be in the form of base + index * constant
    # base + (rax+rax<<1)<<8

    if expr.args[0].op == 'BVV':
        return state.solver.eval(expr.args[0]), expr.args[1]
    elif expr.args[1].op == 'BVV':
        return state.solver.eval(expr.args[1]), expr.args[0]
    else:
        return None, None

# access_repr(expr, deps=state.globals["deps"], trace=state.globals["trace"])
# r = access_tree(expr, state.globals["deps"], state.globals["trace"], {})

# https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function#:~:text=Fowler%E2%80%93Noll%E2%80%93Vo%20is%20a,and%20Phong%20Vo%20in%201991.
def fnv64(data):
    hash_ = 0xcbf29ce484222325
    for b in data:
        hash_ *= 0x100000001b3
        hash_ &= 0xffffffffffffffff
        hash_ ^= ord(b)
    return hash_

class AccessNode:
    OPPOSITE = {
        "__eq__": "__ne__",
        "__ne__": "__eq__",
        "__lt__": "__ge__",
        "__ge__": "__lt__",
        "__le__": "__gt__",
        "__gt__": "__le__",
    }

    def __init__(self, op, args):
        self.op = op
        self.args = args
        self._hash = fnv64(str(self))

    def match(self, other, depth=0):
        """
        <__eq__ <read <__add__ <read <__add__ <read <__add__ <BVS userClient>, <BVV 264>>>, <BVV 8>>>, <BVV 8>>>, <Reverse <Extract <BVS AppleUpstreamUserClient_connection_0>>>>
        <__ne__ <read <__add__ <read <__add__ <read <__add__ <BVS userClient>, <BVV 264>>>, <BVV 8>>>, <BVV 8>>>, <Reverse <Extract <BVS input_223_1024>>>>
        """
        if self.op != other.op:
            if depth != 0:
                return False
            if self.op not in AccessNode.OPPOSITE:
                return False
            if AccessNode.OPPOSITE[self.op] != other.op:
                return False

        if self.op == "BVS":
            # We assume there is only one variable, and thus we only have one pair.
            return True
        if self.op == "BVV":
            return self.args[0] == other.args[0]
        if self.op == "Extract":
            if self.args[2].op == "BVS":
                return self.args[2].match(other.args[2], depth+1)
            else:
                return self.args[0] == other.args[0] and self.args[1] == other.args[1] and \
                    self.args[2].match(other.args[2], depth+1)

        for i in range(len(self.args)):
            if not self.args[i].match(other.args[i], depth+1):
                return False
        return True

    def qualify(self):
        # At least we should have one read
        if self.op == "read":
            return True

        for arg in self.args:
            if isinstance(arg, AccessNode) and arg.qualify():
                return True
        return False

    def __str__(self):
        if self.op == "Extract" and self.args[2].op == "BVS":
            return "<{} {}>".format(self.op, str(self.args[2]))
        return "<{} {}>".format(self.op, ", ".join(map(str, self.args)))

    def __hash__(self):
        return self._hash

    def __eq__(self, other):
        return self.op == other.op and self._hash == other._hash

def access_tree(expr, deps, trace, cache):
    if expr in cache:
        return cache[expr]

    if isinstance(expr, int):
        return AccessNode("BVV", [expr])

    ret = None
    if expr.op == 'BVS':
        if expr.args[0].startswith("tmp_"):
            m = TMP_PATTERN.match(expr.args[0])
            if m:
                addr = int(m.group(1), 16)
                if addr == 0:
                    return AccessNode("BVS", ["userClient"])
                elif addr in trace:
                    _, parent_expr = trace[addr]
                    ret = AccessNode("read", [access_tree(parent_expr, deps, trace, cache)])
                    # return "{}{}".format(args[0], '{%s}' % ', '.join(extras) if extras else '')
        if ret is None:
            ret = AccessNode("BVS", [expr.args[0]])
    elif expr.op == 'BVV':
        ret = AccessNode("BVV", [expr.args[0]])
    elif expr.op == 'Extract':
        if expr.args[2].op == 'BVS' and expr.args[2]._encoded_name in deps:
            for (r, l, resource) in deps[expr.args[2]._encoded_name]:
                if r >= expr.args[0] and l <= expr.args[1]:
                    ret = AccessNode("Extract", [expr.args[0], expr.args[1], AccessNode("BVS", [resource])])
                    break
        if ret is None:
            ret = AccessNode('Extract', [expr.args[0], expr.args[1], access_tree(expr.args[2], deps, trace, cache)])
    else:
        ret = AccessNode(expr.op, [access_tree(each, deps, trace, cache) for each in expr.args])

    cache[expr] = ret
    return ret

# From claripy
def access_repr(expr, max_depth=8, explicit_length=False, details=Base.LITE_REPR, inner=False, parent_prec=15, left=True, deps={}, trace={}):
    """
    Returns a string representation of this AST, but with a maximum depth to
    prevent floods of text being printed.
    :param max_depth:           The maximum depth to print.
    :param explicit_length:     Print lengths of BVV arguments.
    :param details:             An integer value specifying how detailed the output should be:
                                    LITE_REPR - print short repr for both operations and BVs,
                                    MID_REPR  - print full repr for operations and short for BVs,
                                    FULL_REPR - print full repr of both operations and BVs.
    :param inner:               whether or not it is an inner AST
    :param parent_prec:         parent operation precedence level
    :param left:                whether or not it is a left AST
    :returns:                   A string representing the AST
    """
    if max_depth is not None and max_depth <= 0:
            return '<...>'

    elif expr.op in operations.reversed_ops:
        op = operations.reversed_ops[expr.op]
        args = reversed(expr.args)
    else:
        op = expr.op
        args = expr.args

    next_max_depth = max_depth-1 if max_depth is not None else None
    length = expr.length if explicit_length else None
    # if operation is not in op_precedence, assign the "least operation precedence"
    op_prec = operations.op_precedence[op] if op in operations.op_precedence else 15

    args = [access_repr(arg, next_max_depth, explicit_length, details, True, op_prec, idx == 0, deps, trace) \
            if isinstance(arg, Base) else arg for idx, arg in enumerate(args)]

    prec_diff = parent_prec - op_prec
    inner_infix_use_par = prec_diff < 0 or prec_diff == 0 and not left
    inner_repr = _op_repr(op, args, inner, length, details, inner_infix_use_par, deps, trace)

    if not inner:
        return "<{} {}>".format(expr._type_name(), inner_repr)
    else:
        return inner_repr

def get_tmp_var(expr):
    for leaf in expr.leaf_asts():
        if leaf.op == "BVS" and leaf.args[0].startswith("tmp_"):
            m = TMP_PATTERN.match(leaf.args[0])
            if m:
                return int(m.group(1), 16)
            raise Exception("failed to get addr: %s" % leaf.args[0])
    return None

def _op_repr(op, args, inner, length, details, inner_infix_use_par, deps, trace):
    if details < Base.FULL_REPR:
        if op == 'BVS':
            extras = []
            if args[1] is not None:
                fmt = '%#x' if type(args[1]) is int else '%s'
                extras.append("min=%s" % (fmt % args[1]))
            if args[2] is not None:
                fmt = '%#x' if type(args[2]) is int else '%s'
                extras.append("max=%s" % (fmt % args[2]))
            if args[3] is not None:
                fmt = '%#x' if type(args[3]) is int else '%s'
                extras.append("stride=%s" % (fmt % args[3]))
            if args[4] is True:
                extras.append("UNINITIALIZED")
            if args[0].startswith("tmp_"):
                m = TMP_PATTERN.match(args[0])
                if m:
                    addr = int(m.group(1), 16)
                    if addr == 0:
                        return "userClient"
                    elif addr in trace:
                        _, parent_expr = trace[addr]
                        return "*" + access_repr(parent_expr, deps=deps, trace=trace)
                        # return "{}{}".format(args[0], '{%s}' % ', '.join(extras) if extras else '')
            return "{}{}".format(args[0], '{%s}' % ', '.join(extras) if extras else '')

        elif op == 'BoolV':
            return str(args[0])

        elif op == 'BVV':
            if args[0] is None:
                value = '!'
            elif args[1] < 10:
                value = format(args[0], '')
            else:
                value = format(args[0], '#x')
            return value + '#%d' % length if length is not None else value

    if details < Base.MID_REPR:
        if op == 'If':
            value = 'if {} then {} else {}'.format(args[0], args[1], args[2])
            return '({})'.format(value) if inner else value

        elif op == 'Not':
            return '!{}'.format(args[0])

        elif op == 'Extract':
            return '{}[{}:{}]'.format(args[2], args[0], args[1])

        elif op == 'ZeroExt':
            value = '0#{} .. {}'.format(args[0], args[1])
            return '({})'.format(value) if inner else value

        elif op in operations.prefix:
            assert len(args) == 1
            value = '{}{}'.format(operations.prefix[op], args[0])
            return '({})'.format(value) if inner and inner_infix_use_par else value

        elif op in operations.infix:
            value = ' {} '.format(operations.infix[op]).join(args)
            return '({})'.format(value) if inner and inner_infix_use_par else value

    return '{}({})'.format(op, ', '.join(map(str, args)))

def get_sym_var(expr, prefix):
    for leaf in expr.leaf_asts():
        if leaf.op == "BVS" and leaf.args[0].startswith(prefix):
            m = re.match(r"^%s_([\da-f]+)_" % prefix, leaf.args[0])
            if m:
                return int(m.group(1), 16)
            raise Exception("failed to get addr: %s" % leaf.args[0])
    return None

