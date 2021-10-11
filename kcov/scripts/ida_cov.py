
from idautils import *
from idaapi import *
from idc import *

import json

idaapi.auto_wait()

image_base = idaapi.get_imagebase()

def getBlocks(start, end):
    ret = []
    for block in idaapi.FlowChart(idaapi.get_func(funcea)):
        if start <= block.startEA < end and is_code(getFlags(block.startEA)):
            # print(hex(block.startEA))
            ret.append(block.startEA)
    return ret

uncover = []
funcs = list(Functions())
for i in range(len(funcs)-1):
    funcea = funcs[i]
    if idc.get_segm_name(funcea) != "__text":
        continue
    # print("func at 0x%x" % funcea)
    uncover += getBlocks(funcea, funcs[i+1])

# print("func at 0x%x" % funcs[-1])
uncover += getBlocks(funcs[-1], idc.SegEnd(funcs[-1]))

info = []
info.append({
    "uncover": uncover,
    "cover": [],
    "kext": "",
    "binary": ""
})

with open("cov.json", "w") as fp:
    json.dump({"info": info}, fp)

Exit(0)