#! /bin/bash

set -e

source common.sh

pip3 install virtualenv
brew install ldid
brew install clang-format

virtualenv ${SYZGEN} --python=$(which python3)

# install golang
# https://golang.org/doc/install
if [[ ! -f "go1.15.6.darwin-amd64.tar.gz" ]]; then
    curl -o go1.15.6.darwin-amd64.tar.gz https://dl.google.com/go/go1.15.6.darwin-amd64.tar.gz
    tar -xzf go1.15.6.darwin-amd64.tar.gz
fi

echo "GOROOT=\"${GOROOT}\"" >> $VIRTUAL_ENV
echo "export GOROOT" >> $VIRTUAL_ENV
echo "GOPATH=\"${GOPATH}\"" >> $VIRTUAL_ENV
echo "export GOPATH" >> $VIRTUAL_ENV

git clone git@github.com:CvvT/SyzGen.git
mkdir ${GOPATH}
git clone git@github.com:CvvT/bluetooth-fuzzer.git ${GOPATH}/src/github.com/google/syzkaller

# install custom angr
git clone git@github.com:angr/angr.git
cp angr.patch angr/
cd angr
git checkout -b dev ce14b4dd70f64
git apply angr.patch
rm angr.patch

