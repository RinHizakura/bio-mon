use crate::bump_memlock_rlimit::*;
use std::mem::MaybeUninit;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use lazy_static::lazy_static;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};

mod bump_memlock_rlimit;

#[path = "../bpf/.output/biomon.skel.rs"]
mod biomon;
use biomon::*;

lazy_static! {
    static ref running: Arc<AtomicBool> = Arc::new(AtomicBool::new(true));
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

    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {}

    Ok(())
}
