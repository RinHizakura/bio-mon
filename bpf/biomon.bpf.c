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
    u64 data_len;
} req_t;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, hash_key_t);
    __type(value, req_t);
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
    req_t req;
    dev_t dev = args->dev;
    char rwbs[RWBS_LEN];
    sector_t sector = args->sector;

    bpf_probe_read(&rwbs, RWBS_LEN, args->rwbs);
    rwflag = get_rwflag_tp(rwbs);

    key = (hash_key_t){
        .dev = dev,
        .rwflag = rwflag,
        .sector = sector,
    };

    req = (req_t){
        .ts = ts,
        .data_len = 0,
    };

    bpf_map_update_elem(&req_info, &key, &req, BPF_ANY);
    return 0;
}

SEC("tracepoint/block/block_io_done")
int block_io_done(struct trace_event_raw_block_rq *args)
{
    pid_t pid = (bpf_get_current_pid_tgid() >> 32);
    u64 ts = bpf_ktime_get_ns();
    u32 rwflag;
    dev_t dev = args->dev;
    char rwbs[RWBS_LEN];
    sector_t sector = args->sector;
    hash_key_t key;
    req_t *req;
    msg_ent_t *ent;

    bpf_probe_read(&rwbs, RWBS_LEN, args->rwbs);
    rwflag = get_rwflag_tp(rwbs);

    key = (hash_key_t){
        .dev = dev,
        .rwflag = rwflag,
        .sector = sector,
    };

    req = bpf_map_lookup_elem(&req_info, &key);
    if (req) {
        ts -= req->ts;
        bpf_map_delete_elem(&req_info, &key);
    } else
        ts = 0;

    bpf_printk("(%-3d,%-3d) %-8s %-10d time=%-10d(ms)", MAJOR(dev), MINOR(dev),
               rwbs, sector, ts / 1000);

    ent = bpf_ringbuf_reserve(&msg_ringbuf, sizeof(msg_ent_t), 0);
    if (ent) {
        ent->id = MSG_ID++;
        ent->ts = ts;
        ent->pid = pid;
        ent->sector = sector;
        ent->dev = dev;
        ent->rwflag = rwflag;
        bpf_get_current_comm(&ent->comm, sizeof(ent->comm));
        bpf_ringbuf_submit(ent, 0);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
