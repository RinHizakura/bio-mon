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

#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)

#define MAJOR(dev) ((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev) ((unsigned int) ((dev) &MINORMASK))

#define RWBS_LEN 8

/* Note: the parameter of a tracepoint can be  by the
 * first arguments of DEFINE_EVENT(block_rq, block_io_start, ...) */
SEC("tracepoint/block/block_io_start")
int block_io_start(struct trace_event_raw_block_rq *args)
{
    u64 ts = bpf_ktime_get_ns();
    dev_t dev = args->dev;
    char *rwbs = args->rwbs;
    sector_t sector = args->sector;

    u32 dev_major = MAJOR(dev);
    u32 dev_minor = MINOR(dev);

    bpf_printk("[%-10lld] block_io_start: (%-3d,%-3d) %-8s %-10d", ts,
               dev_major, dev_minor, rwbs, sector);

    return 0;
}

SEC("tracepoint/block/block_io_done")
int block_io_done(struct trace_event_raw_block_rq *args)
{
    u64 ts = bpf_ktime_get_ns();
    dev_t dev = args->dev;
    char *rwbs = args->rwbs;
    sector_t sector = args->sector;

    u32 dev_major = MAJOR(dev);
    u32 dev_minor = MINOR(dev);

    bpf_printk("[%-10lld] block_io_done: (%-3d,%-3d) %-8s %-10d", ts, dev_major,
               dev_minor, rwbs, sector);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
