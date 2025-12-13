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
#include "msg.h"

#define MINORBITS 20
#define MINORMASK ((1U << MINORBITS) - 1)

#define MAJOR(dev) ((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev) ((unsigned int) ((dev) &MINORMASK))

#define REQ_OP_BITS 8
#define REQ_OP_MASK ((1 << REQ_OP_BITS) - 1)

typedef struct {
    dev_t dev;
    u32 rwflag;
    sector_t sector;
} hash_key_t;

typedef struct {
    u64 ts;
    u64 len;
} start_req_t;

typedef struct {
    u64 ts;
    u64 len;
    u32 pid;
    char comm[TASK_COMM_LEN];
} io_t;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, hash_key_t);
    __type(value, start_req_t);
} start_req_info SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, hash_key_t);
    __type(value, io_t);
} io_info SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 10240);
} msg_ringbuf SEC(".maps");

u64 MSG_ID = 0;

static int get_rwflag(u32 cmd_flags)
{
    // FIXME: Need to consider kernel version
    return !!((cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);
}

static dev_t ddevt(struct gendisk *disk)
{
    return (BPF_CORE_READ(disk, major) << 20) |
           BPF_CORE_READ(disk, first_minor);
}

SEC("kprobe/blk_mq_start_request")
int BPF_KPROBE(blk_mq_start_request, struct request *req)
{
    struct pt_regs UNUSED *_ctx = ctx;
    struct gendisk *disk = BPF_CORE_READ(req, q, disk);

    hash_key_t key = (hash_key_t){
        .dev = ddevt(disk),
        .rwflag = get_rwflag(BPF_CORE_READ(req, cmd_flags)),
        .sector = BPF_CORE_READ(req, __sector),
    };

    start_req_t start_req = (start_req_t){
        .ts = bpf_ktime_get_ns(),
        .len = BPF_CORE_READ(req, __data_len),
    };
    bpf_map_update_elem(&start_req_info, &key, &start_req, BPF_ANY);

    return 0;
}

static int get_rwflag_tp(char *rwbs)
{
    int i = 0;
    while (i < RWBS_LEN && rwbs[i] != '\0') {
        if (rwbs[i] == 'W')
            return 1;

        i++;
    }
    return 0;
}

/* Note: the parameter of a tracepoint can be  by the
 * first arguments of DEFINE_EVENT(block_rq, block_io_start, ...) */
SEC("tracepoint/block/block_io_start")
int block_io_start(struct trace_event_raw_block_rq *args)
{
    u32 rwflag;
    hash_key_t key;
    io_t io;
    dev_t dev = args->dev;
    char rwbs[RWBS_LEN];
    sector_t sector = args->sector;

    /* Ignore this I/O if it fails to get its pid */
    if (bpf_get_current_comm(&io.comm, sizeof(io.comm)))
        return 0;

    bpf_probe_read(&rwbs, RWBS_LEN, args->rwbs);
    rwflag = get_rwflag_tp(rwbs);

    key = (hash_key_t){
        .dev = dev,
        .rwflag = rwflag,
        .sector = sector,
    };

    io.ts = bpf_ktime_get_ns();
    io.len = args->bytes;
    io.pid = bpf_get_current_pid_tgid() >> 32;

    bpf_map_update_elem(&io_info, &key, &io, BPF_ANY);
    return 0;
}

SEC("tracepoint/block/block_io_done")
int block_io_done(struct trace_event_raw_block_rq *args)
{
    u64 ts;
    u32 rwflag;
    dev_t dev = args->dev;
    char rwbs[RWBS_LEN];
    sector_t sector = args->sector;
    hash_key_t key;
    start_req_t *start_req;
    io_t *io;
    msg_ent_t *ent;

    bpf_probe_read(&rwbs, RWBS_LEN, args->rwbs);
    rwflag = get_rwflag_tp(rwbs);

    key = (hash_key_t){
        .dev = dev,
        .rwflag = rwflag,
        .sector = sector,
    };

    start_req = bpf_map_lookup_elem(&start_req_info, &key);
    if (!start_req)
        return 0;

    ent = bpf_ringbuf_reserve(&msg_ringbuf, sizeof(msg_ent_t), 0);
    if (!ent) {
        bpf_map_delete_elem(&start_req_info, &key);
        bpf_map_delete_elem(&io_info, &key);
        return 0;
    }
    ts = bpf_ktime_get_ns();
    ent->id = MSG_ID++;
    ent->delta = ts - start_req->ts;
    ent->ts_ms = ts / 1000;
    ent->qlen = start_req->len;

    io = bpf_map_lookup_elem(&io_info, &key);
    if (io) {
        ent->pid = io->pid;
        ent->sector = sector;
        ent->io_len = io->len;
        ent->dev = dev;
        ent->rwflag = rwflag;
        memcpy(ent->comm, io->comm, sizeof(io->comm));
    }

    bpf_ringbuf_submit(ent, 0);
    bpf_map_delete_elem(&start_req_info, &key);
    bpf_map_delete_elem(&io_info, &key);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
