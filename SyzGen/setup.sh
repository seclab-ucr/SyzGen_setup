#! /bin/bash

set -e

if [ $(uname -s) = "Darwin" ]; then
    brew install ldid

    # install jtool2
    if [[ ! -f "jtool2.tgz" ]]; then
        curl -o jtool2.tgz http://www.newosxbook.com/tools/jtool2.tgz
        mkdir jtool2
        tar -xzf jtool2.tgz -C jtool2
    fi

    # install demumble
    if [[ ! -f "demumble-mac.zip" ]]; then
        # OR wget --no-check-certificate --content-disposition 
        curl -LJO https://github.com/nico/demumble/releases/download/v1.2.2/demumble-mac.zip
        unzip -o -d libs/ demumble-mac.zip
    fi
fi

pip install -r requirements.txt

cd libs
make
cd ..