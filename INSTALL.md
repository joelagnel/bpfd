# Install and run BCC tools and BPFd from a package

If you only care about running/adding/modifying new BCC tools and don't care about changing the core infrastructure of
BCC/clang/BPFd code, download the [`bpfd-full.deb`](http://bit.do/bpfd-full-dl) file. This package contains BCC
tools, LLVM libraries and BPFd ready to go. All source code for these binaries are available in Joel's github repositories.

Note that the .deb package is only for Ubuntu 64-bit x86 machines.

Once downloaded, run:
```
dpkg -i bcc-full.deb
```
This will install all the binaries into an isolated `/usr/local/bpfd-install/` directory. With the exception being a
`/usr/bin/bcc-init` required to start the BCC environment sandbox.

Start the sandbox by running following as root:
```
sudo bcc-init
```
This gets you a shell prompt that looks like this:
```
(bcc) root@hostname:~/
```
Next setup your target environment based on your needs. For this the `bcc-set` command convinently helps.
The following settings are mandatory unless you're planning to run BCC locally.

Setup the path to the kernel source directory. Make sure the kernel build has completed atleast once in the source
directory, and take note of the path to it.
```
bcc-set --kernelsrc /path/to/kernel-sources/
```

Setup the architecture of your target:
```
bcc-set --arch "arm64"
```
Setup the remote communication method, for Android devices you'd use 'adb'. In the future other networking protocols may
be trivially added.
```
bcc-set --remote "adb"
```
To check all settings made so far, you can run:
```
bcc-set --print
```
You can set the remote to "process" if you just want to run bpfd locally in a forked "process", which is probably only
good for some local BPFd testing.

Next in order to run the tool, you'll need to push BPFd binary to your target device. This really depends on the type of
remote you're using. For the `adb` remote, `bpfd` binary is expected at `/data/bpfd`. For sake of convenience, an arm64
binary comes with the .deb package. Run the following to copy it to over to your arm64 Android device if that's what
you're testing on:
```
adb push /usr/local/bpfd-install/share/bpfd.arm64.static /data/bpfd
```
You should be all set. All BCC tools are available in the $PATH and ready to run from your sandbox. Try simple tools
like `opensnoop` or `filetop` to make sure its working. For debugging, run the following commands before running the
tools. This will show you flags passed to the kernel build, path to the kernel, messages communicated to BPFd, etc.
```
bcc-set --debug
```
To stop debugging, run:
```
bcc-set --nodebug
```
#### Apply Kernel Patch to speed up stack traces
A kernel patch is needed to speed-up StackMap look ups. Its been tested on x86 and arm64. Please
[download it](https://raw.githubusercontent.com/joelagnel/bpfd/master/patches/kernel/0001-bpf-stackmap-Implement-bpf_get_next_key.patch)
and rebuild your kernel.

<a name="diy"></a>
# (Alternately, IF you want to) Build and running everything yourself
This is an example of a typical build and installation procedure, it should be fairly straight forward to get these steps
working for other remotes or architectures. For this example, we'll refer to the machine where you do all your
development and have your kernel sources available as the `development machine` and the machine you're tracing as the
`target`.

### Install build dependencies
```
sudo apt-get install cmake zlib-devel libelf-dev bison flex iperf netperf
```

### Build LLVM on your development host
```
git clone http://llvm.org/git/llvm.git
cd llvm/tools; git clone http://llvm.org/git/clang.git
cd ..; mkdir -p build/install; cd build
cmake -G "Unix Makefiles" -DLLVM_TARGETS_TO_BUILD="BPF;X86" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$PWD/install ..
make
make install
export PATH=$PWD/install/bin:$PATH
```
LLVM's libraries are needed to run BCC tools. Add the last line above to your `.bashrc` to keep it persistent.

### Build BCC tools on your development host
These steps were executed on Ubuntu distro. If they don't work for your distro, [check BCC project's
INSTALL.md](https://github.com/iovisor/bcc/blob/master/INSTALL.md) for other instructions.
```
git clone https://github.com/joelagnel/bcc.git
cd bcc
git checkout -b bcc-bpfd origin/bcc-bpfd
mkdir -p build; cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr ..
make
make install
```

If you're planning on running BCC's unit tests (i.e. by using `make test`), you will also need to install pyroute2:
```
git clone https://github.com/svinota/pyroute2.git
cd pyroute2
sudo make install
```

### Build/Install BPFd for your target machine
You must build BPFd differently depending on the architecture of the target machine.

#### To build BPFd for x86
```
git clone https://github.com/joelagnel/bpfd.git; cd bpfd
mkdir -p build; cd build
cmake ..
make
```

#### To build BPFd for arm64
Here, we make use of the `aarch64-linux-gnu` toolchain, which you can install on Ubuntu via:
```
sudo apt-get install g++-aarch64-linux-gnu
```

The commands below were executed with the assumption that the `aarch64-linux-gnu` toolchain is located in the `/usr/` directory.
Please make the appropriate changes in the commands below if that assumption does not hold true for you.

You first need to build zlib for arm64:
```
git clone https://github.com/madler/zlib.git; cd zlib
export CROSS_PREFIX=aarch64-linux-gnu-
./configure --prefix=/usr/aarch64-linux-gnu/
make
sudo make install
```

You also need to build elfutils for arm64:
```
git clone git://sourceware.org/git/elfutils.git; cd elfutils
autoreconf -i -f

# Build elfutils for x86 first since we need an x86 copy of i386_gendis to build elfutils for arm64
./configure --enable-maintainer-mode
make
cp ./libcpu/i386_gendis ~/

# Build elfutils for arm64
./configure --host=aarch64-linux-gnu --prefix=/usr/aarch64-linux-gnu/ --enable-maintainer-mode
cp ~/i386_gendis ./libcpu/i386_gendis
make
sudo make install
```

Once all the dependencies are ready, you can then finally build BPFd for arm64:
```
git clone https://github.com/joelagnel/bpfd.git; cd bpfd
mkdir -p build; cd build
cmake -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchain-aarch64.cmake ..
make
```

The built binaries are available in the build directory.

In case of errors when building for arm64, check that the path to the `aarch64-linux-gnu` toolchain in `toolchain-aarch64.cmake` is suitable for your distribution.

#### Installation
Installation really depends on the remote target. For arm64, copy the `build/bpfd` to your bin/ directory. For Android
arm64 devices, push bpfd to the data partition by running:
```
adb push build/bpfd /data/
```

### Apply Kernel Patch to speed up stack traces
A kernel patch is needed to speed-up StackMap look ups. Its been tested on x86 and arm64. Please
[download it](https://raw.githubusercontent.com/joelagnel/bpfd/master/patches/kernel/0001-bpf-stackmap-Implement-bpf_get_next_key.patch)
and rebuild your kernel.

### Prepare your kernel sources
Make sure the kernel sources are available on your development machine somewhere, and that the kernel build has
completed atleast once in the kernel source directory.

### Setup environment variables and run tools
The following environment variables need to be setup:
- `ARCH` should point to the architecture of the `target` such as `x86` or `arm64`.
- `BCC_KERNEL_SOURCE` should point to the kernel source directory.
- `BCC_REMOTE` should point to the remote mechanism such as `adb`.

If you'd like to set the environment variables more easily, you can use the `bcc-set` and `bcc-env` tools. Simply copy
both of them from the cloned BPFd sources in `scripts/setup-scripts/` to your dev machine's `bin` directory. Check the
above instructions on how to use `bcc-set`.

You can also source the example .rc files from my BCC tree. Two example environment variable settings are provided for
sourcing. Here's one for [adb interface with an arm64 Android
target](https://github.com/joelagnel/bcc/blob/bcc-bpfd/arm64-adb.rc) and another one for a [local x86 target with a
process remote](https://github.com/joelagnel/bcc/blob/bcc-bpfd/x86-local.rc).

You should be all set, try running simple tools like `opensnoop` or `syscount`. For debugging, you could set the
following environment variables and check the output.

To debug kernel build process (path to kernel sources, flags):
```
export BCC_KBUILD_DEBUG=1
```
To debug BCC remote communications with BPFd, run:
```
export BCC_REMOTE_DEBUG=1
```
