# bio-mon

# Introduction

The `bio-mon` is an experimental tool to trace block I/O activity like
[biosnoop](https://github.com/iovisor/bcc/blob/master/tools/biosnoop.py), but implementing
by [BPF CO-RE](https://docs.ebpf.io/concepts/core/) instead of relying on
[bcc](https://github.com/iovisor/bcc/tree/master).

