use crate::bump_memlock_rlimit::*;
use std::mem::MaybeUninit;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use lazy_static::lazy_static;
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use plain::Plain;

mod bump_memlock_rlimit;

#[path = "../bpf/.output/biomon.skel.rs"]
mod biomon;
use biomon::*;

lazy_static! {
    static ref running: Arc<AtomicBool> = Arc::new(AtomicBool::new(true));
}

const TASK_COMM_LEN: usize = 16;
#[repr(C)]
struct MsgEnt {
    id: u64,
    ts: u64,
    pid: u64,
    sector: u64,
    dev: u32,
    rwflag: u32,
    comm: [u8; TASK_COMM_LEN],
}
unsafe impl Plain for MsgEnt {}

fn format_cmd(buf: &[u8; TASK_COMM_LEN]) -> String {
    let len = buf.len();
    let mut idx = 0;

    let mut s = String::new();
    s.push('"');
    while idx < len {
        let c = buf[idx];
        if c == 0 {
            break;
        } else {
            s.push(c as char);
        }

        idx += 1;
    }

    /* If we can't find the ended zero in the buffer, this is an incomplete string. */
    let extra = if idx >= len { "..." } else { "" };
    s.push_str(&format!("\"{}", extra));
    s
}

fn cast<T: plain::Plain>(args: &[u8]) -> &T {
    let size = std::mem::size_of::<T>();
    let slice = &args[0..size];
    return plain::from_bytes::<T>(slice).expect("Fail to cast bytes");
}

fn msg_handler(bytes: &[u8]) -> i32 {
    let ent_size = size_of::<MsgEnt>();
    let ent = &bytes[0..ent_size];

    let ent: &MsgEnt = cast(ent);
    let ts = ent.ts;
    let pid = ent.pid;
    let sector = ent.sector;
    let dev = ent.dev;
    let rwflag = ent.rwflag;
    let comm = &ent.comm;

    print!("{:<14}", ts);
    print!(" {:<14}", &format_cmd(comm));
    print!(" {:<6}", pid);
    print!(" {:<7}", dev);
    print!(" {:<2}", rwflag);
    print!(" {:<10}", sector);
    print!(" {:<7}", 0);
    println!(" {:<7}", 0);

    0
}

fn rb_callback(bytes: &[u8]) -> i32 {
    if !running.load(Ordering::SeqCst) {
        return 1;
    }

    msg_handler(bytes)
}

fn main() -> Result<()> {
    /* We may have to bump RLIMIT_MEMLOCK for libbpf explicitly */
    if cfg!(bump_memlock_rlimit_manually) {
        bump_memlock_rlimit()?;
    }

    let mut open_object = MaybeUninit::uninit();
    let builder = BiomonSkelBuilder::default();
    /* Open BPF application */
    let open_skel = builder.open(&mut open_object)?;

    /* Load & verify BPF programs */
    let mut skel = open_skel.load()?;
    /* Attach tracepoint handler */
    let _tracepoint = skel.attach()?;

    let mut builder = RingBufferBuilder::new();
    let msg_ringbuf = skel.maps.msg_ringbuf;
    builder.add(&msg_ringbuf, rb_callback)?;
    let msg = builder.build()?;

    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    println!(
        "{:<14} {:<14} {:<6} {:<7} {:<2} {:<10} {:<7} {:<7}",
        "TIME(s)", "COMM", "PID", "DISK", "T", "SECTOR", "BYTES", "LAT(ms)"
    );

    while running.load(Ordering::SeqCst) {
        let result = msg.poll(Duration::MAX);
        if let Err(_r) = &result {
            return result.map_err(anyhow::Error::msg);
        }
    }

    Ok(())
}
