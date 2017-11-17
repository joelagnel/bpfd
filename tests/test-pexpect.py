#!/usr/bin/env python

import pexpect as pe

c = pe.spawn('/home/joel/repo/bpfd/run_bpfd.sh')

"""
send_command: Send a command to a fork of bpfd

@c: pexpect client with an initiatilized session
@cmd: Command to send bpfd, doesn't need newline.

Return: An array of strings returned by bpfd.
"""
def send_command(c, cmd):
    print("sending command: {}".format(cmd));
    c.sendline(cmd)
    c.expect('END_BPFD_OUTPUT')

    ret = c.before.split('\n')

    # Sanitize command output
    ret = [r.rstrip() for r in ret if r]

    i = 0;
    while (ret[i].startswith('START_BPFD_OUTPUT') != True):
        i = i + 1

    return ret[(i+1):]

print send_command(c, 'foo')
print send_command(c, 'BPF_CREATE_MAP 1 8 40 10240 0')
print send_command(c, 'bar baz')
print send_command(c, 'BPF_CREATE_MAP 1 8 40 10240 0')

bpf_prog = "BPF_PROG_LOAD 2 248 GPL 264721 eRdwAAAAAAC3AQAAAAAAAHsa+P8AAAAAexrw/wAAAAB7Guj/AAAAAHsa4P8AAAAAexrY/wAAAACFAAAADgAAAL8GAAAAAAAAe2rQ/wAAAAC/oQAAAAAAAAcBAADo////twIAABAAAACFAAAAEAAAAGcAAAAgAAAAdwAAACAAAABVAAwAAAAAAHtq2P8AAAAAhQAAAAUAAAB7CuD/AAAAAHt6+P8AAAAAGBEAAAMAAAAAAAAAAAAAAL+iAAAAAAAABwIAAND///+/owAAAAAAAAcDAADY////twQAAAAAAACFAAAAAgAAALcAAAAAAAAAlQAAAAAAAAA="

print send_command(c, bpf_prog)
print send_command(c, 'READ_AVAILABLE_FILTER_FUNCTIONS /sys/kernel/debug/tracing')
