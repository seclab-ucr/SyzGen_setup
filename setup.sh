#! /bin/bash

set -e

source common.sh

# common libraries
pip3 install virtualenv

# OS specific
OS=$(uname -s)
case $OS in
    Linux)
        echo "Detect Linux OS"
        OS="linux"
    ;;
    Darwin)
        echo "Detect Darwin OS"
        OS="darwin"
        brew install ldid
        brew install clang-format
    ;;
    *)
        echo "unknown" && exit 1
    ;;
esac

GO_URL="https://dl.google.com/go/go1.15.6.${OS}-amd64.tar.gz"

virtualenv ${SYZGEN} --python=$(which python3)

# install golang
# https://golang.org/doc/install
if [[ ! -f "go1.15.6.${OS}-amd64.tar.gz" ]]; then
    curl -o go1.15.6.${OS}-amd64.tar.gz ${GO_URL}
    tar -xzf go1.15.6.${OS}-amd64.tar.gz
fi

echo "GOROOT=\"${GOROOT}\"" >> $VIRTUAL_ENV
echo "export GOROOT" >> $VIRTUAL_ENV
echo "GOPATH=\"${GOPATH}\"" >> $VIRTUAL_ENV
echo "export GOPATH" >> $VIRTUAL_ENV

echo "installing SyzGen..."
git clone git@github.com:seclab-ucr/SyzGen.git
cd SyzGen
sh setup.sh
cd ..

git clone git@github.com:CvvT/kcov.git

echo "installing syzkaller..."
mkdir ${GOPATH}
git clone --branch macos git@github.com:CvvT/syzkaller.git ${GOPATH}/src/github.com/google/syzkaller

source ${VIRTUAL_ENV}

echo "installing angr..."
# install custom cle to support macOS driver
git clone git@github.com:angr/cle.git
cp cle.patch cle/
cd cle
git checkout -b dev 8cfedc60f8cc219d
git apply cle.patch
rm cle.patch
pip install .
cd ..

# install custom angr
git clone git@github.com:angr/angr.git
cp angr.patch angr/
cd angr
git checkout -b dev ce14b4dd70f64
git apply angr.patch
rm angr.patch
pip install .
cd ..

# install angr-targets
git clone git@github.com:angr/angr-targets.git
cd angr-targets
pip install -e .
cd ..

echo run "source ${SYZGEN}/bin/active" to set up the env
echo "Please use xcode to build kcov"

