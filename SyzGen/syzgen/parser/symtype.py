
import json
import logging
import math

from functools import reduce

from claripy.ast.bv import Reverse, Extract
from syzgen.parser.types import int2bytes

logger = logging.getLogger(__name__)

class SymType(object):
    """
    Re-construct structure given the final state and the top-level symbol.
    """
    def __init__(self, symbol, fuzzy=False): # size in bits
        self.symbol = symbol
        self.fuzzy = fuzzy  # We didn't reach the final state, hence some info is not accurate.
        if isinstance(symbol, str):
            self.fields = [{"type": "ptr", "size": 8}]
        else:
            self.fields = [{"type": "buffer", "left": symbol.length-1, "right": 0}] # big-endian
        
    def get_symbolic_variable(self, state, *key):
        v = list(state.solver.get_variables(*key))
        if len(v) > 0:
            return v[0][1]
        return None

    def get_dependences(self, state):
        if isinstance(self.symbol, str):
            return []

        deps = state.globals.get("deps", dict())
        sym_name = self.symbol._encoded_name
        deps = deps[sym_name] if sym_name in deps else []
        return deps

    def get_ranges(self, state):
        ret = []
        for each in state.locals.get("variables", set()):
            if each[0] == self.symbol._encoded_name:
                ret.append(each)

        # Prefer field with larger size because one field may be accessed byte by byte.
        overlapped = []
        for i in range(len(ret)):
            found = False
            for j in range(len(ret)):
                if i == j:
                    continue

                if ret[i][1] <= ret[j][1] and ret[i][2] >= ret[j][2]:
                    found = True
                    break
            if not found:
                overlapped.append(ret[i])
        return overlapped
    
    def initialize(self, state, solver_state):
        if isinstance(self.symbol, str):
            ptr_sym = self.get_symbolic_variable(state, self.symbol)
            if ptr_sym is not None:
                self.fields[0]["ref"] = SymType(ptr_sym, fuzzy=self.fuzzy)
                self.fields[0]["ref"].initialize(state, solver_state)
            else:
                raise Exception("unknown variable %s" % self.symbol)
        else:
            ranges = self.get_ranges(state)
            for name, left, right in ranges:
                self.refine(left, right)
                
            # We may find out new dependence which should also be field.
            # Note dependence field should not be split into multiple fields.
            deps = self.get_dependences(state)
            for (l, r, resc_name) in deps:
                self.refine(l, r)

            self.evaluate(state, solver_state)
        
    def refine(self, left, right):
        """Split existing field if we find its subfield has been accessed,
        and merge consecutive fields if they are assessed as a whole.
        """
        for index, each in enumerate(self.fields):
            if each["left"] >= left and each["right"] <= right:
                if "access" in each and each["access"]:
                    continue

                new_fields = []
                if each["left"] > left:
                    new_fields.append({"type": "buffer", "left": each["left"], "right": left+1})
                new_fields.append({"type": "buffer", "left": left, "right": right, "access": True})
                if each["right"] < right:
                    new_fields.append({"type": "buffer", "left": right-1, "right": each["right"]})
                del self.fields[index]
                for i in range(len(new_fields)):
                    self.fields.insert(index+i, new_fields[i])
                break
            elif each["left"] >= right and left >= each["right"]:
                # overlapping
                if "access" in each and each["access"]:
                    continue
                new_fields = []
                if each["left"] >= left:   
                    if each["left"] > left:
                        new_fields.append({"type": "buffer", "left": each["left"], "right": left+1})
                    new_fields.append({"type": "buffer", "left": left, "right": each["right"], "access": True})
                else:
                    new_fields.append({"type": "buffer", "left": each["left"], "right": max(right, each["right"]), "access": True})
                    if each["right"] < right:
                        new_fields.append({"type": "buffer", "left": right-1, "right": each["right"]})
                del self.fields[index]
                for i in range(len(new_fields)):
                    self.fields.insert(index+i, new_fields[i])
                break

        new_field = {"type": "buffer", "left": 0, "right": float('inf'), "access": True}
        indices = []
        for index, each in enumerate(self.fields):
            if each["left"] <= left and each["right"] >= right:
                new_field["left"] = max(each["left"], new_field["left"])
                new_field["right"] = min(each["right"], new_field["right"])
                indices.append(index)

        if new_field["left"] != left or new_field["right"] != right:
            # from IPython import embed; embed()
            logger.warning("one access overlaps multiple fields")
        if len(indices) > 1:
            for index in reversed(indices):
                del self.fields[index]
            self.fields.insert(indices[0], new_field)
    
    def evaluate(self, state, solver_state):
        # We may find out new dependence through type inference
        sym_name = self.symbol._encoded_name
        deps = self.get_dependences(state)
        strings = state.locals.get("strings", set())
        lens = state.locals.get("lens", {})
        
        for i, field in enumerate(self.fields):
            size = (field["left"] - field["right"] + 1) // 8
            field["size"] = size

            if "access" not in field:
                if self.fuzzy:
                    # We may miss some field because we didn't execute all the way through.
                    field["access"] = True
                continue

            for (l, r, resource) in deps:
                # detect dependence
                if field["left"] == l and field["right"] == r:
                    field["type"] = "resource"
                    field["name"] = resource
                    break

            print(sym_name, field["left"], field["right"])
            if (sym_name, field["left"], field["right"]) in strings:
                print("find a string")
                field["type"] = "string"

            sym = Extract(field["left"], field["right"], self.symbol)
            if size == 8 and field["type"] == "buffer": # it could be a pointer
                concrete = state.solver.eval(Reverse(sym))
                print("evaluate", sym, concrete)
                ptr_sym = self.get_symbolic_variable(state, "mem", concrete)
                # print(concrete, ptr_sym)
                if ptr_sym is not None:
                    field["type"] = "ptr"
                    field["ref"] = SymType(ptr_sym, fuzzy=self.fuzzy)
                    field["ref"].initialize(state, solver_state)
                    
            if field["type"] not in ["ptr", "resource"] and size <= 8 and not self.fuzzy and i < 64:
                # TODO: concretization during symbolic execution introduce unnecessary constraints,
                # which misleads us to believe it is a constant. Hence, we should rule this out.
                field["min"] = solver_state.solver.min(Reverse(sym))
                field["max"] = solver_state.solver.max(Reverse(sym))
                if field["min"] == field["max"]:
                    # detect constant
                    field["type"] = "const"
                elif field["min"] != 0 or field["max"] != ((1<<size*8)-1):
                    # Flag or Range value
                    # Check if it is range: use simple heuristics
                    # FIXME: 1. XXXX00 the LSB is zero and XXXX is not zero.
                    res1 = solver_state.solver.eval_upto(Reverse(sym) == field["min"]+1, 2)
                    res2 = solver_state.solver.eval_upto(Reverse(sym) == field["max"]-1, 2)
                    # print(res1, res2)
                    if True in res1 and True in res2:
                        field["type"] = "range"
                        field["stride"] = 1
                        # TODO: check range with stride
                    else:
                        # Binary search to find out maximum number of possible values
                        num = 4
                        while num < 256:
                            solutions = solver_state.solver.eval_upto(Reverse(sym), num)
                            if len(solutions) < num:
                                break
                            num = num*2
                        if num == 256:
                            # Too many possible values
                            print(sym, field)
                            print(solutions)
                            logger.warning("Too many possible values")
                            field["type"] = "range"
                            field["stride"] = reduce(math.gcd, solutions) or 1
                        else:
                            field["type"] = "flag"
                            field["values"] = solutions

                # k = (sym_name, field["left"], field["right"])
                # if k in lens:
                #     print("find a length")
                #     if "attrs" not in field:
                #         field["attrs"] = {}
                #     field["attrs"]["len"] = lens[k]
                for key, val in lens.items():
                    if key[0] != sym_name:
                        continue
                    if field["left"] >= key[1] and field["right"] <= key[2]:
                        print("find a length", key, val)
                        if "attrs" not in field:
                            field["attrs"] = {}
                        field["attrs"]["len"] = val
                        break

            field["data"] = int2bytes(solver_state.solver.eval(Reverse(sym)), size)
            
    def refineLen(self, path, ptrs={}):
        if not isinstance(self.symbol, str):
            ptrs[self.symbol._encoded_name] = {
                "path": list(path),
                "length": self.symbol.length
            }

        # FIXME: the order is critical.
        offset = 0
        for field in self.fields:
            path.append(offset)
            if field["type"] == "ptr":
                field["ref"].refineLen(list(path), ptrs)
            offset += field["size"]
            path.pop()

        for field in self.fields:
            if "attrs" in field and "len" in field["attrs"]:
                sym, l, r, scale = field["attrs"]["len"]
                if sym not in ptrs:
                    raise Exception("Can not find %s" % sym)
                offset = (ptrs[sym]["length"]-l-1) // 8
                field["path"] = list(ptrs[sym]["path"]) + [offset]
                field["bitSize"] = scale*8


    def toJson(self):
        struct = []
        offset = 0
        for field in self.fields:
            new_field = dict(field)
            new_field["offset"] = offset
            
            if "access" not in field:
                new_field["access"] = False  # default
            
            if field["type"] == "ptr":
                new_field["ref"] = field["ref"].toJson()
                new_field["size"] = 8
            elif field["type"] in ["buffer", "resource", "const", "range", "flag", "string"]:
                new_field["size"] = (field["left"] - field["right"] + 1) // 8
                if "data" not in field:
                    new_field["data"] = [0xff] * new_field["size"]  # dummy data
            else:
                raise Exception("unknown type: %s" % field["type"])
            offset += new_field["size"]
            struct.append(new_field)

        if len(struct) == 1:
            return struct[0]
        return {"type": "struct", "fields": struct, "offset": 0, "size": offset}

    def repr(self):
        ret = {
            "fields": []
        }
        for field in self.fields:
            each = dict()
            for k, v in field.items():
                if k == "ref":
                    each["ref"] = v.repr()
                elif k != "attrs":
                    each[k] = v
            ret["fields"].append(each)
        return json.dumps(ret)
        # return json.dumps(self.toJson())
