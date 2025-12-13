#ifndef MSG_H
#define MSG_H

#include "common.h"

#define TASK_COMM_LEN 16
typedef struct {
    u64 id;
    u64 ts_ms;
    u64 delta;
    u64 pid;
    u64 sector;
    u64 qlen;
    u64 io_len;
    u32 dev;
    u32 rwflag;
    char comm[TASK_COMM_LEN];
} msg_ent_t;

#endif
