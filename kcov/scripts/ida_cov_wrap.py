
import os
import argparse
import subprocess

IDA64 = "C:\\Program Files\\IDA 7.2\\idat64.exe"

def run(filepath):
    script = os.path.join(os.getcwd(), "scripts", "ida_cov.py")
    subprocess.run([IDA64, "-A", "-S\"%s\"" % script, filepath, "-t"], check=True)
    # cov = os.path.join(os.path.dirname(filepath), "cov.json")
    # dst = os.path.join("workdir", "cc", f)
    # os.replace(cov, "cov.json")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="main")
    parser.add_argument("--path", help="path to the binary")
    args = parser.parse_args()
    run(args.path)
