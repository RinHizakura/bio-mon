# bio-mon

## Overview

The `bio-mon` is an experimental tool to trace block I/O activity like
[biosnoop](https://github.com/iovisor/bcc/blob/master/tools/biosnoop.py), but implementing
by [BPF CO-RE](https://docs.ebpf.io/concepts/core/) instead of relying on
[bcc](https://github.com/iovisor/bcc/tree/master).

## I/O Trace Information

For each I/O trace, it includes the following information:

Field      | Description
-----------|------------------
TIME(s)    | Timestamp of the I/O in seconds from the start of tracing
COMM       | Name of the process that issued the I/O
PID        | PID of the process that issued the I/O
DISK       | Name of the disk device
SECTOR     | Starting sector number of the I/O
BYTES      | Number of bytes transferred to the device by `request`
IOBYTES    | Number of bytes of `bio` to the block layer
P          | Pattern of the I/O operation (R: random, S: sequential)
QUE(ms)    | Time spent from `bio` queued until the issued request is completed
LAT(ms)    | Time from `request` is issued to the device driver until it is completed
