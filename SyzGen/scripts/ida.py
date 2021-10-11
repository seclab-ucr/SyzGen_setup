
import argparse
import os
import subprocess
import struct
import xml.etree.ElementTree as ET

IDA64 = "C:\\Program Files\\IDA 7.2\\idat64.exe"
BlackList = [
    "com.apple.iokit.IOSurface",  # frequently triggerred
    "com.apple.driver.AGPM" # unable to parse the driver
]

def getBundleIdentifier(path):
    tree = ET.parse(path)
    root = tree.getroot()
    info = root[0]
    size = len(info)
    i = 0
    while i < size:
        node = info[i]
        if node.tag == "key":
            if node.text == "CFBundleIdentifier":
                value = info[i+1]
                return value.text
            i += 2
        else:
            i += 1
    return None

MH_MAGIC = 0xfeedface
MH_MAGIC_64 = 0xfeedfacf
def isMacho(filepath):
    with open(filepath, "rb") as f:
        magic = struct.unpack("I", f.read(4))[0]
        return magic == MH_MAGIC_64

def getInfo2(path):
    plist = os.path.join(path, "Info.plist")
    if not os.path.exists(plist):
        return None, None

    identifier = getBundleIdentifier(plist)
    for name in os.listdir(path):
        _, ext = os.path.splitext(name)
        filepath = os.path.join(path, name)
        if ext == "" and not os.path.isdir(filepath) and isMacho(filepath):
            return identifier, filepath
    return None, None

def getInfo(path):
    plist = os.path.join(path, "Contents", "Info.plist")
    kext = os.path.join(path, "Contents", "MacOS")
    if not os.path.exists(kext):
        # Try the other structure
        return getInfo2(path)

    identifier = getBundleIdentifier(plist)
    for name in os.listdir(kext):
        _, ext = os.path.splitext(name)
        filepath = os.path.join(kext, name)
        if ext == "" and not os.path.isdir(filepath) and isMacho(filepath):
            return identifier, filepath
    return None, None

def analyze_signature(filepath):
    d, f = os.path.split(filepath)
    # cc = os.path.join(d, "cc.json")
    dst = os.path.join("workdir", "cc", f)
    if os.path.exists(dst):
        return

    # "C:\Program Files\IDA 7.2\ida64.exe" -A -S"C:\Users\weite\Desktop\getcc.py IOHIDFamily" 
    # C:\Users\weite\Desktop\10.15.4\IOHIDFamily.kext\Contents\MacOS\IOHIDFamily -t
    script = os.path.join(os.getcwd(), "scripts", "ida_getcc.py")
    cmd = [IDA64, "-A", "-S\"%s\"" % script, filepath, "-t"]
    print(" ".join(cmd))
    subprocess.run(cmd, check=True)
    
    os.replace("cc.json", dst)

def run(path):
    for name in os.listdir(path):
        # if name != "IOHIDFamily.kext":
        #     continue

        identifier, binary = getInfo(os.path.join(path, name))
        print(identifier, binary)
        if identifier and identifier not in BlackList:
            print(binary, identifier)
            analyze_signature(binary)

        plugins = os.path.join(path, name, "Contents", "Plugins")
        if os.path.exists(plugins):
            run(plugins)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="main")
    parser.add_argument('-d', '--dir', help="path to dir")
    args = parser.parse_args()

    if args.dir:
        print(args.dir)
        run(args.dir)