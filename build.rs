//! Build-time metadata capture for the `version` subcommand.
//!
//! Injects `OIXC_COMMIT_ID` (short git hash, with a `-dirty` suffix when the
//! working tree has uncommitted changes; `unknown` when git is unavailable or
//! the source is not a checkout) and `OIXC_BUILD_TIME` (UTC wall-clock
//! timestamp). `SOURCE_DATE_EPOCH` is honored for reproducible builds.
//!
//! No `cargo:rerun-if-*` directives are emitted, so the default rule applies:
//! the script re-runs whenever any package file changes, which keeps the
//! commit id fresh across rebuilds.

use std::env;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    println!("cargo:rustc-env=OIXC_COMMIT_ID={}", commit_id());
    println!("cargo:rustc-env=OIXC_BUILD_TIME={}", build_time());
}

fn commit_id() -> String {
    let Some(hash) = git(&["rev-parse", "--short=12", "HEAD"]) else {
        return "unknown".to_string();
    };
    let dirty = git(&["status", "--porcelain"]).is_some_and(|status| !status.trim().is_empty());
    if dirty { format!("{hash}-dirty") } else { hash }
}

fn build_time() -> String {
    let secs = match env::var("SOURCE_DATE_EPOCH") {
        Ok(value) => value.parse::<i64>().unwrap_or_else(|_| now_secs()),
        Err(_) => now_secs(),
    };
    format_utc(secs)
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

fn format_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC")
}

/// Days since 1970-01-01 to (year, month, day). Howard Hinnant's
/// `civil_from_days` algorithm; valid for the full i64 range.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_097) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if month <= 2 { y + 1 } else { y }, month, day)
}

fn git(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
}
