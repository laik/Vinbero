#!/bin/bash

version=$(uname -r)
KERNEL_VERSION="v${version:0:3}"

root_dir=$(pwd)
echo $KERNEL_VERSION
rm -rf build
mkdir build

git clone --branch $KERNEL_VERSION --depth 1 https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git ./build/linux
pushd ./build/linux
make defconfig
make headers_install
popd
mkdir out
