/* clang-format off */
/* These header file should be included first and in sequence,
 * because our following included file may depend on these. Turn
 * off clang-format to achieve this purpose. */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
/* clang-format on */

#include "common.h"

SEC("tracepoint/block/block_rq_insert")
int sys_enter(UNUSED struct pt_regs *ctx)
{
    bpf_printk("block_rq_insert");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
