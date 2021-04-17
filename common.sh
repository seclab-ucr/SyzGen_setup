
WORKDIR=${PWD}
SYZGEN="fuzz"
VIRTUAL_ENV=${SYZGEN}/bin/activate

GOROOT="${WORKDIR}/go"
GOPATH="${WORKDIR}/gopath"
SYZKALLER_DIR=${GOPATH}/src/github.com/google/syzkaller

