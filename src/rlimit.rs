use std::io;

#[cfg(unix)]
use libc::{RLIM_INFINITY, RLIMIT_NOFILE, rlim_t, rlimit};

/// Raise `RLIMIT_NOFILE` as high as this process is allowed to go.
///
/// Tries a true unlimited limit first, then the OS-specific ceiling
/// (`kern.maxfilesperproc` on macOS), then the current hard limit.
/// Failure is reported on stderr and never aborts startup.
pub fn raise_nofile_limit() {
    #[cfg(unix)]
    if let Err(error) = raise_nofile_limit_unix() {
        eprintln!("failed to raise RLIMIT_NOFILE: {error}");
    }
}

#[cfg(unix)]
fn raise_nofile_limit_unix() -> io::Result<()> {
    let current = get_nofile()?;
    if current.rlim_cur == RLIM_INFINITY {
        return Ok(());
    }

    if set_nofile(RLIM_INFINITY, RLIM_INFINITY).is_ok() {
        return Ok(());
    }

    if current.rlim_max == RLIM_INFINITY && set_nofile(RLIM_INFINITY, current.rlim_max).is_ok() {
        return Ok(());
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    if let Some(max) = darwin_maxfilesperproc() {
        let hard = clamp_to_hard(max, current.rlim_max);
        if set_nofile(hard, preferred_hard(hard, current.rlim_max)).is_ok() {
            return Ok(());
        }
    }

    if current.rlim_max == RLIM_INFINITY {
        const LARGE: rlim_t = 1 << 20;
        if set_nofile(LARGE, RLIM_INFINITY).is_ok() {
            return Ok(());
        }
    } else if current.rlim_cur < current.rlim_max {
        set_nofile(current.rlim_max, current.rlim_max)?;
    }

    Ok(())
}

#[cfg(unix)]
fn clamp_to_hard(wanted: rlim_t, hard: rlim_t) -> rlim_t {
    if hard == RLIM_INFINITY || wanted <= hard {
        wanted
    } else {
        hard
    }
}

#[cfg(unix)]
fn preferred_hard(soft: rlim_t, hard: rlim_t) -> rlim_t {
    if hard == RLIM_INFINITY { soft } else { hard }
}

#[cfg(unix)]
fn get_nofile() -> io::Result<rlimit> {
    let mut lim = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a valid `rlimit` used only as an out-parameter.
    if unsafe { libc::getrlimit(RLIMIT_NOFILE, &mut lim) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(lim)
}

#[cfg(unix)]
fn set_nofile(soft: rlim_t, hard: rlim_t) -> io::Result<()> {
    let lim = rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };
    // SAFETY: `lim` is a well-formed `rlimit` for `RLIMIT_NOFILE`.
    if unsafe { libc::setrlimit(RLIMIT_NOFILE, &lim) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn darwin_maxfilesperproc() -> Option<rlim_t> {
    let mut value: libc::c_int = 0;
    let mut size = std::mem::size_of_val(&value);
    // SAFETY: `sysctlbyname` writes a `c_int` into `value` when the name exists.
    let rc = unsafe {
        libc::sysctlbyname(
            c"kern.maxfilesperproc".as_ptr(),
            (&raw mut value).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    (rc == 0 && value > 0).then_some(value as rlim_t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn raises_nofile_soft_limit_to_the_allowed_ceiling() {
        let before = get_nofile().unwrap();
        raise_nofile_limit();
        let after = get_nofile().unwrap();
        assert!(after.rlim_cur >= before.rlim_cur);
        assert_ne!(after.rlim_cur, 0);
        if before.rlim_max != RLIM_INFINITY {
            assert!(after.rlim_cur <= after.rlim_max);
            assert_eq!(after.rlim_cur, after.rlim_max);
        }
    }
}
