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

typedef struct {
    dev_t dev;
    u32 rwflag;
    sector_t sector;
} hash_key_t;

typedef struct {
    u64 ts;
    u32 pid;
    char comm[TASK_COMM_LEN];
} val_t;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, hash_key_t);
    __type(value, val_t);
} req_info SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 10240);
} msg_ringbuf SEC(".maps");

u64 MSG_ID = 0;

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
    u64 ts = bpf_ktime_get_ns();
    u32 rwflag;
    hash_key_t key;
    val_t val;
    dev_t dev = args->dev;
    char rwbs[RWBS_LEN];
    sector_t sector = args->sector;

    /* Ignore this I/O if it fails to get its pid */
    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)))
        return 0;

    bpf_probe_read(&rwbs, RWBS_LEN, args->rwbs);
    rwflag = get_rwflag_tp(rwbs);

    key = (hash_key_t){
        .dev = dev,
        .rwflag = rwflag,
        .sector = sector,
    };

    val.ts = ts;
    val.pid = bpf_get_current_pid_tgid() >> 32;

    bpf_map_update_elem(&req_info, &key, &val, BPF_ANY);
    return 0;
}

SEC("tracepoint/block/block_io_done")
int block_io_done(struct trace_event_raw_block_rq *args)
{
    u64 ts = bpf_ktime_get_ns();
    u32 rwflag;
    dev_t dev = args->dev;
    char rwbs[RWBS_LEN];
    sector_t sector = args->sector;
    hash_key_t key;
    val_t *val;
    msg_ent_t *ent;

    bpf_probe_read(&rwbs, RWBS_LEN, args->rwbs);
    rwflag = get_rwflag_tp(rwbs);

    key = (hash_key_t){
        .dev = dev,
        .rwflag = rwflag,
        .sector = sector,
    };

    val = bpf_map_lookup_elem(&req_info, &key);
    if (val) {
        ent = bpf_ringbuf_reserve(&msg_ringbuf, sizeof(msg_ent_t), 0);
        if (ent) {
            ent->id = MSG_ID++;
            ent->delta = ts - val->ts;
            ent->ts_ms = ts / 1000;
            ent->pid = val->pid;
            ent->sector = sector;
            ent->dev = dev;
            ent->rwflag = rwflag;
            memcpy(ent->comm, val->comm, sizeof(val->comm));
            bpf_ringbuf_submit(ent, 0);
        }

        bpf_map_delete_elem(&req_info, &key);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
