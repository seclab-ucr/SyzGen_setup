
import os

from ..config import ServicePath, ModelPath, PoCPath
from ..utils import loads

# ./bin/syz-manager -config workdir/cfg_AppleFDEKeyStoreUserClient.json -bpcov 
# -kcov kcov -corpus 2>&1 | tee corpus.txt

class Prog:
    def __init__(self):
        self.covers = []
        self.prog = []

def hasValidService(line):
    if line.startswith("syz_IOConnectCallMethod"):
        start = line.index("(")+1
        end = line.index(",")
        service = line[start:end].strip()
        if service == "0x0":
            # print(line)
            return False
    return True

def parse_corpus(filepath):
    progs = []
    cur = Prog()
    with open(filepath, "r") as fp:
        isprog = False
        for line in fp:
            line = line.strip()
            if "cov:" in line:
                substr = line[line.index("cov:")+len("cov:"):]
                substr = substr.strip()
                cur.covers.append(int(substr, 16))
            if "executing program:" in line:
                isprog = True
                substr = line[line.index("executing program:")+len("executing program:"):]
                substr = substr.strip()
                if hasValidService(substr):
                    cur.prog.append(substr)
                continue

            if isprog:
                if len(line) == 0:
                    isprog = False
                    progs.append(cur)
                    cur = Prog()
                else:
                    if hasValidService(line):
                        cur.prog.append(line)

    return progs

def generate_corpus(filepath, client):
    progs = parse_corpus(filepath)
    # for prog in progs:
    #     print(prog.covers)
    #     print(prog.prog)

    dispathTable = loads(os.path.join(ServicePath, client.metaClass))
    for cmd, method in dispathTable.methods.items():
        for prog in progs:
            if method.addr in prog.covers:
                # TODO: differantiate call and async call
                path = os.path.join(PoCPath, "%s_Group%d_0.syz" % (client.metaClass, cmd))
                with open(path, "w") as fp:
                    fp.write("\n".join(prog.prog))
                break

