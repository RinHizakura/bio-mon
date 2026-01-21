use std::collections::HashMap;
use std::fs::read_to_string;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use lazy_static::lazy_static;
use libbpf_rs::RingBufferBuilder;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use plain::Plain;

#[path = "../bpf/.output/biomon.skel.rs"]
mod biomon;
use biomon::*;

#[derive(Parser)]
struct Cli {
    #[arg(short, long, help = "Name of target block device to trace, e.g. sda")]
    device: Option<String>,
}

lazy_static! {
    static ref running: Arc<AtomicBool> = Arc::new(AtomicBool::new(true));
    static ref diskmap: Mutex<HashMap<u32, String>> = Mutex::new(HashMap::new());
}
static START_TS: OnceLock<u64> = OnceLock::new();

fn create_diskinfo(target_dev: Option<String>) -> Result<Option<u32>> {
    let mut m = diskmap.lock().unwrap();
    let mut filter_dev: Option<u32> = None;

    let f = read_to_string("/proc/diskstats")?;
    for line in f.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let major: u32 = tokens[0].parse().unwrap();
        let minor: u32 = tokens[1].parse().unwrap();
        let device_name = tokens[2];
        let dev = major << 20 | minor;

        if target_dev.is_some() {
            if device_name == target_dev.as_ref().unwrap() {
                filter_dev = Some(dev);
            }
        }

        m.insert(dev, device_name.to_owned());
    }

    Ok(filter_dev)
}

const TASK_COMM_LEN: usize = 16;
#[repr(C)]
struct MsgEnt {
    id: u64,
    ts_ms: u64,
    delta: u64,
    qdelta: u64,
    pid: u64,
    sector: u64,
    qlen: u64,
    io_len: u64,
    dev: u32,
    rwflag: u32,
    comm: [u8; TASK_COMM_LEN],
    pattern: u8,
}
unsafe impl Plain for MsgEnt {}

fn format_cmd(buf: &[u8; TASK_COMM_LEN]) -> String {
    let len = buf.len();
    let mut idx = 0;

    let mut s = String::new();
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
    s.push_str(&format!("{}", extra));
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
    let ts = ent.ts_ms;
    let pid = ent.pid;
    let sector = ent.sector;
    let qlen = ent.qlen;
    let io_len = ent.io_len;
    let dev = ent.dev;
    let rwflag = ent.rwflag;
    let pattern = ent.pattern;
    let comm = &ent.comm;
    let delta = ent.delta;
    let qdelta = ent.qdelta;
    let m = diskmap.lock().unwrap();
    let start_ts = START_TS.get_or_init(|| ts);

    println!(
        "{:<12} {:<16} {:<6} {:<9} {:<2} {:<10} {:<8} {:<8} {:<2} {:<7.2} {:<7.2}",
        (ts - start_ts) as f32 / 1000000.0,
        &format_cmd(comm),
        pid,
        m.get(&dev).unwrap_or(&"<unknown>".to_string()),
        if rwflag == 1 { "W" } else { "R" },
        sector,
        qlen,
        io_len,
        pattern as char,
        qdelta as f32 / 1000000.0,
        delta as f32 / 1000000.0,
    );

    0
}

fn rb_callback(bytes: &[u8]) -> i32 {
    if !running.load(Ordering::SeqCst) {
        return 1;
    }

    msg_handler(bytes)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let target_dev = cli.device;

    let filter_dev = create_diskinfo(target_dev)?;

    let mut open_object = MaybeUninit::uninit();
    let builder = BiomonSkelBuilder::default();
    /* Open BPF application */
    let mut open_skel = builder.open(&mut open_object)?;

    if let Some(dev) = filter_dev {
        let rodata = open_skel
            .maps
            .rodata_data
            .as_deref_mut()
            .expect("`rodata` is not memory mapped");
        rodata.filter_dev = dev;
    }

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
        "{:<12} {:<16} {:<6} {:<9} {:<2} {:<10} {:<8} {:<8} {:<2} {:<7} {:<7}",
        "TIME(s)",
        "COMM",
        "PID",
        "DISK",
        "T",
        "SECTOR",
        "BYTES",
        "IOBYTES",
        "P",
        "QUE(ms)",
        "LAT(ms)"
    );

    while running.load(Ordering::SeqCst) {
        let result = msg.poll(Duration::MAX);
        if let Err(_r) = &result {
            return result.map_err(anyhow::Error::msg);
        }
    }

    Ok(())
}
