#!/usr/bin/env python

import pexpect as pe

c = pe.spawn('/home/joel/repo/bpfd/run_bpfd.sh')

def send_command(c, cmd):
    print("sending command: {}".format(cmd));
    c.sendline(cmd)
    c.expect('\r\n')
    c.expect('\r\n')
    print("[{}]\n".format(c.before))

send_command(c, 'foo')
send_command(c, 'BPF_CREATE_MAP 1 8 40 10240 0')
send_command(c, 'bar baz')
send_command(c, 'BPF_CREATE_MAP 1 8 40 10240 0')

bpf_prog = "BPF_PROG_LOAD 2 248 GPL 264721 eRdwAAAAAAC3AQAAAAAAAHsa+P8AAAAAexrw/wAAAAB7Guj/AAAAAHsa4P8AAAAAexrY/wAAAACFAAAADgAAAL8GAAAAAAAAe2rQ/wAAAAC/oQAAAAAAAAcBAADo////twIAABAAAACFAAAAEAAAAGcAAAAgAAAAdwAAACAAAABVAAwAAAAAAHtq2P8AAAAAhQAAAAUAAAB7CuD/AAAAAHt6+P8AAAAAGBEAAAMAAAAAAAAAAAAAAL+iAAAAAAAABwIAAND///+/owAAAAAAAAcDAADY////twQAAAAAAACFAAAAAgAAALcAAAAAAAAAlQAAAAAAAAA="

send_command(c, bpf_prog)
