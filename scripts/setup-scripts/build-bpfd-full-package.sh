#!/bin/sh -x
# A script I use to build the bpfd-full debian package mentioned in INSTALL.md

cd $HOME/repo/

sudo rsync -ravu $HOME/repo/bcc/build/bccpackage/ $HOME/repo/bpfd-full/
sudo rsync -ravu $HOME/repo/llvm/build/llvm-package/ $HOME/repo/bpfd-full/

sudo cp $HOME/repo/bpfd/build/bpfd $HOME/repo/bpfd-full/usr/local/bpfd-install/bin/
sudo cp $HOME/repo/bpfd/build/libbpf_bpfd.so $HOME/repo/bpfd-full/usr/local/bpfd-install/lib/
sudo cp $HOME/repo/bpfd.arm64 $HOME/repo/bpfd-full/usr/local/bpfd-install/share/

sudo cp $HOME/repo/bpfd/scripts/setup-scripts/bcc-init $HOME/repo/bpfd-full/usr/bin/
sudo cp $HOME/repo/bpfd/scripts/setup-scripts/bcc-env $HOME/repo/bpfd-full/usr/local/bpfd-install/bin/
sudo cp $HOME/repo/bpfd/scripts/setup-scripts/bcc.bash.rc $HOME/repo/bpfd-full/usr/local/bpfd-install/share/
sudo cp $HOME/repo/bpfd/scripts/setup-scripts/deb.control $HOME/repo/bpfd-full/DEBIAN/control

sudo chown -R root:root $HOME/repo/bpfd-full/
sudo chmod 0755 $HOME/repo/bpfd-full/DEBIAN/control

sudo dpkg-deb --build bpfd-full
