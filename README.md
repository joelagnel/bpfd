## BPFd (Berkeley Packet Filter Daemon)

Deprecation Warning:
If you're looking for running BCC on Android devices, please look at [BCC using
Androdeb](https://github.com/joelagnel/androdeb/blob/master/BCC.md) instead.
BPFd is not undergoing active development at the moment, and Android has
switched to using androdeb for running BCC. However BPFd is still available in
this repository and if you want to use BPFd with BCC, please look at this [pull
request](https://github.com/iovisor/bcc/pull/1675) to get needed BCC support.

BPFd faciliates easier loading of eBPF programs using simple stdio interface.

One of the main usescases of this work is easier running of BCC tools across
system and architecture boundaries for cross-development.

Before this project's birth, the BCC tools architecture was as follows: ![BCC
architecture](images/bcc-arch.png) 

BPFd based invocations partition this, thus making it possible to do
cross-development and execution of the tools across machine and architecture
boundaries. For instance, kernel sources that the BCC tools depend on can be on
a development machine, with eBPF code being loaded onto a remote machine. This
paritioning is illustrated in the following diagram ![BCC architecture with
BPFd](images/bcc-with-bpfd-arch.png) 

An article is in the works to explain the history and design more. Meanwhile
look at `INSTALL.md` for easy to install package downloads, or
slightly-more-compilicated build yourself instructions.

This project is very early, please help by submitting patches or documentation.
Check the issue list!
