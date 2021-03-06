
import argparse
import json
import os
import struct

def generate_coverage(json_paths, outpath):
    """ format for kcov:
    struct head {
        uint64_t    num_of_drivers;
        kcov_head_t drivers[num_of_drivers];
    }
    struct kcov_head_t {
        char      name[64];
        uint64_t  num_of_addrs;
        uint64_t  addrs[num_of_addrs];
    }
    """
    if outpath is None:
        # default dir for output
        try:
            os.mkdir("out")
        except:
            pass
        outpath = "out/kcov"

    total = 0
    with open(outpath, "wb") as fd:
        fd.write(struct.pack("<Q", len(json_paths)))
        for path in json_paths:
            name = os.path.basename(path)
            with open(path, "r") as fp:
                info = json.load(fp)
                print("Parsing %s ..." % info["kext"])
                bs = [ord(x) for x in info["kext"]]
                for i in range(64-len(bs)):
                    bs.append(0)
                fd.write(struct.pack("64B", *bs))
                fd.write(struct.pack("<Q", len(info["uncover"])))
                total += len(info["uncover"])
                for addr in info["uncover"]:
                    fd.write(struct.pack("<Q", addr))
    print("total coverage: %d" % total)
    print("Genereated %s" % outpath)
    print("Please upload %s to the tested machine at the path /tmp/kcov" % outpath)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', "--outpath", help="path to the output")
    parser.add_argument("json_path", nargs="+", help="path to the json files generated by ida_cov.py")

    args = parser.parse_args()
    generate_coverage(args.json_path, args.outpath)

