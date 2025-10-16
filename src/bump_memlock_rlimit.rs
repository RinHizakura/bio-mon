use anyhow::{Result, anyhow};
use libc::{RLIM_INFINITY, RLIMIT_MEMLOCK, rlimit, setrlimit};
use std::io::Error;

pub fn bump_memlock_rlimit() -> Result<()> {
    let rlim = rlimit {
        rlim_cur: RLIM_INFINITY,
        rlim_max: RLIM_INFINITY,
    };

    unsafe {
        let ret = setrlimit(RLIMIT_MEMLOCK, &rlim);
        if ret != 0 {
            return Err(anyhow!(format!(
                "Failed to bump RLIMIT_MEMLOCK: {}",
                Error::last_os_error()
            )));
        }
    }

    Ok(())
}
