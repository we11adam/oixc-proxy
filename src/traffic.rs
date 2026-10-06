//! Local, minute-sampled application traffic. No credentials or destinations are stored.
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, mpsc};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

const MAX_LINE: usize = 1024;
static ACTIVE: OnceLock<Arc<Counters>> = OnceLock::new();

#[derive(Default)]
struct Counters {
    enabled: AtomicBool,
    values: [AtomicU64; 4],
}

#[derive(Clone, Copy)]
pub(crate) enum Direction {
    TcpUpload = 0,
    TcpDownload = 1,
    UdpUpload = 2,
    UdpDownload = 3,
}

pub(crate) fn record(direction: Direction, bytes: usize) {
    if bytes != 0 {
        if let Some(counters) = ACTIVE.get() {
            if counters.enabled.load(Ordering::Relaxed) {
                counters.values[direction as usize].fetch_add(bytes as u64, Ordering::Relaxed);
            }
        }
    }
}

impl Counters {
    fn snapshot(&self) -> Bytes {
        Bytes {
            tcp_upload: self.values[0].load(Ordering::Relaxed),
            tcp_download: self.values[1].load(Ordering::Relaxed),
            udp_upload: self.values[2].load(Ordering::Relaxed),
            udp_download: self.values[3].load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, Default, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Bytes {
    pub tcp_upload: u64,
    pub tcp_download: u64,
    pub udp_upload: u64,
    pub udp_download: u64,
}

impl Bytes {
    fn delta(self, previous: Self) -> Self {
        Self {
            tcp_upload: self.tcp_upload.wrapping_sub(previous.tcp_upload),
            tcp_download: self.tcp_download.wrapping_sub(previous.tcp_download),
            udp_upload: self.udp_upload.wrapping_sub(previous.udp_upload),
            udp_download: self.udp_download.wrapping_sub(previous.udp_download),
        }
    }

    fn add(&mut self, other: Self) -> Result<()> {
        fn sum(a: u64, b: u64) -> Result<u64> {
            a.checked_add(b).context("traffic total exceeds u64")
        }
        self.tcp_upload = sum(self.tcp_upload, other.tcp_upload)?;
        self.tcp_download = sum(self.tcp_download, other.tcp_download)?;
        self.udp_upload = sum(self.udp_upload, other.udp_upload)?;
        self.udp_download = sum(self.udp_download, other.udp_download)?;
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Sample {
    version: u8,
    /// UTC Unix seconds when the counters were sampled, not event timestamps.
    timestamp: u64,
    /// Beginning of the sampling window; can exceed a minute after disk errors.
    since: u64,
    bytes: Bytes,
}

pub fn beside_config(config: &Path) -> PathBuf {
    config
        .parent()
        .unwrap_or(Path::new("."))
        .join("traffic.jsonl")
}

fn open_private(path: &Path, create: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(create)
        .create(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options.open(path).context("open private traffic file")?;
    let metadata = file.metadata()?;
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file() || metadata.mode() & 0o077 != 0 || (uid != 0 && metadata.uid() != uid) {
        bail!("traffic file must be a private regular file owned by the service user");
    }
    Ok(file)
}

struct Journal {
    file: File,
    _lock: File,
    poisoned: bool,
}

fn lock_file(file: &File, operation: i32) -> Result<()> {
    if unsafe { libc::flock(file.as_raw_fd(), operation) } != 0 {
        return Err(std::io::Error::last_os_error()).context("lock traffic journal");
    }
    Ok(())
}

impl Journal {
    fn open(path: &Path) -> Result<Self> {
        let mut lock_path = path.as_os_str().to_os_string();
        lock_path.push(".lock");
        let lock = open_private(Path::new(&lock_path), true)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            bail!(
                "another process is recording to this traffic file; use --traffic-file for a separate instance"
            );
        }
        let mut file = open_private(path, true)?;
        lock_file(&file, libc::LOCK_EX)?;
        // Reject unrelated existing files before attempting any tail recovery.
        let mut first = Vec::new();
        BufReader::new((&mut file).take((MAX_LINE + 1) as u64)).read_until(b'\n', &mut first)?;
        if first.len() > MAX_LINE {
            bail!("traffic journal has an oversized first record");
        }
        if first.last() == Some(&b'\n') {
            decode_sample(&first, 1)?;
        } else if !first.is_empty() && !first.starts_with(b"{\"version\":1,") {
            bail!("existing file is not an oixc-proxy traffic journal");
        }
        // Recover only an incomplete final record. Never silently discard corrupt complete lines.
        let length = file.metadata()?.len();
        let start = length.saturating_sub(MAX_LINE as u64);
        file.seek(SeekFrom::Start(start))?;
        let mut tail = Vec::new();
        file.read_to_end(&mut tail)?;
        if tail.last().is_some_and(|byte| *byte != b'\n') {
            let keep = match tail.iter().rposition(|byte| *byte == b'\n') {
                Some(index) => start + index as u64 + 1,
                None if start == 0 => 0,
                None => bail!("traffic journal has an oversized or corrupt final record"),
            };
            file.set_len(keep)?;
            file.sync_data()?;
            eprintln!("traffic.recovered_incomplete_tail");
        }
        // Validate the last complete record too; do not append to corrupt history.
        let length = file.metadata()?.len();
        let start = length.saturating_sub(MAX_LINE as u64);
        file.seek(SeekFrom::Start(start))?;
        tail.clear();
        file.read_to_end(&mut tail)?;
        if !tail.is_empty() {
            let end = tail.len() - 1;
            let begin = tail[..end]
                .iter()
                .rposition(|byte| *byte == b'\n')
                .map_or(0, |i| i + 1);
            decode_sample(&tail[begin..], 0).context("invalid final traffic record")?;
        }
        file.seek(SeekFrom::End(0))?;
        lock_file(&file, libc::LOCK_UN)?;
        Ok(Self {
            file,
            _lock: lock,
            poisoned: false,
        })
    }

    fn append(&mut self, sample: &Sample) -> Result<()> {
        if self.poisoned {
            bail!("traffic journal requires recovery after a failed rollback");
        }
        let mut bytes = serde_json::to_vec(sample)?;
        bytes.push(b'\n');
        lock_file(&self.file, libc::LOCK_EX)?;
        let result = (|| {
            let offset = self.file.seek(SeekFrom::End(0))?;
            if let Err(error) = self
                .file
                .write_all(&bytes)
                .and_then(|_| self.file.sync_data())
            {
                // Roll back partial writes so the next attempt never duplicates a delta.
                if self
                    .file
                    .set_len(offset)
                    .and_then(|_| self.file.sync_data())
                    .is_err()
                {
                    self.poisoned = true;
                    bail!("traffic append and rollback both failed; restart required for recovery");
                }
                self.file.seek(SeekFrom::Start(offset))?;
                return Err(error).context("persist traffic sample");
            }
            Ok(())
        })();
        result.and(lock_file(&self.file, libc::LOCK_UN))
    }
}

pub struct Recorder {
    counters: Arc<Counters>,
    stop: mpsc::Sender<()>,
    worker: Option<std::thread::JoinHandle<Result<()>>>,
}

impl Recorder {
    pub fn start(path: &Path) -> Result<Self> {
        let journal = Journal::open(path)?;
        let counters = Arc::new(Counters::default());
        ACTIVE
            .set(counters.clone())
            .map_err(|_| anyhow::anyhow!("traffic recorder already initialized"))?;
        let (stop, receiver) = mpsc::channel();
        let state = counters.clone();
        let worker = std::thread::Builder::new()
            .name("oixc-traffic".into())
            .spawn(move || collect(journal, state, receiver))
            .context("start traffic recorder")?;
        counters.enabled.store(true, Ordering::Relaxed);
        Ok(Self {
            counters,
            stop,
            worker: Some(worker),
        })
    }

    pub fn stop(mut self) -> Result<()> {
        self.counters.enabled.store(false, Ordering::Relaxed);
        let _ = self.stop.send(());
        self.worker
            .take()
            .unwrap()
            .join()
            .map_err(|_| anyhow::anyhow!("traffic recorder panicked"))?
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        self.counters.enabled.store(false, Ordering::Relaxed);
        let _ = self.stop.send(());
    }
}

struct Sampler {
    previous: Bytes,
    since: u64,
}

impl Sampler {
    fn flush(&mut self, journal: &mut Journal, counters: &Counters, timestamp: u64) -> Result<()> {
        let current = counters.snapshot();
        let sample = Sample {
            version: 1,
            timestamp,
            since: self.since,
            bytes: current.delta(self.previous),
        };
        journal.append(&sample)?;
        self.previous = current;
        self.since = timestamp;
        Ok(())
    }
}

fn collect(mut journal: Journal, counters: Arc<Counters>, stop: mpsc::Receiver<()>) -> Result<()> {
    let mut sampler = Sampler {
        previous: Bytes::default(),
        since: crate::diagnostics::unix_now(),
    };
    loop {
        let now = crate::diagnostics::unix_now();
        let stopping = !matches!(
            stop.recv_timeout(Duration::from_secs(60 - now % 60)),
            Err(mpsc::RecvTimeoutError::Timeout)
        );
        let timestamp = crate::diagnostics::unix_now();
        match sampler.flush(&mut journal, &counters, timestamp) {
            Ok(()) => {}
            Err(error) if stopping => return Err(error),
            Err(_) => eprintln!("traffic.persist_failed; counters retained for next sample"),
        }
        if stopping {
            return Ok(());
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub from: Option<u64>,
    pub to: Option<u64>,
    pub samples: u64,
    pub first_sample_at: Option<u64>,
    pub last_sample_at: Option<u64>,
    pub bytes: Bytes,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub total_bytes: u64,
    pub sampling_interval_seconds: u64,
    pub extended_windows: u64,
    pub clock_reversals: u64,
    pub incomplete_tail_ignored: bool,
}

pub fn query(path: &Path, from: Option<u64>, to: Option<u64>) -> Result<Report> {
    if from.zip(to).is_some_and(|(from, to)| from >= to) {
        bail!("--from must precede --to");
    }
    let file = open_private(path, false)?;
    lock_file(&file, libc::LOCK_SH)?;
    // Read a fixed snapshot. A concurrent append's incomplete final line is ignored.
    let length = file.metadata()?.len();
    let mut reader = BufReader::new(file.take(length));
    let mut report = Report {
        from,
        to,
        samples: 0,
        first_sample_at: None,
        last_sample_at: None,
        bytes: Bytes::default(),
        upload_bytes: 0,
        download_bytes: 0,
        total_bytes: 0,
        sampling_interval_seconds: 60,
        extended_windows: 0,
        clock_reversals: 0,
        incomplete_tail_ignored: false,
    };
    let mut line = Vec::new();
    let mut index = 0u64;
    loop {
        line.clear();
        let read = reader
            .by_ref()
            .take((MAX_LINE + 1) as u64)
            .read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }
        index += 1;
        if read > MAX_LINE {
            bail!("traffic record {index} exceeds size limit");
        }
        if line.last() != Some(&b'\n') {
            report.incomplete_tail_ignored = true;
            break;
        }
        let sample = decode_sample(&line, index)?;
        if from.is_some_and(|start| sample.timestamp < start)
            || to.is_some_and(|end| sample.timestamp >= end)
        {
            continue;
        }
        report.bytes.add(sample.bytes)?;
        report.samples += 1;
        report.first_sample_at = Some(
            report
                .first_sample_at
                .map_or(sample.timestamp, |t| t.min(sample.timestamp)),
        );
        report.last_sample_at = Some(
            report
                .last_sample_at
                .map_or(sample.timestamp, |t| t.max(sample.timestamp)),
        );
        report.extended_windows += u64::from(sample.timestamp.saturating_sub(sample.since) > 65);
        report.clock_reversals += u64::from(sample.timestamp < sample.since);
    }
    report.upload_bytes = report
        .bytes
        .tcp_upload
        .checked_add(report.bytes.udp_upload)
        .context("traffic total exceeds u64")?;
    report.download_bytes = report
        .bytes
        .tcp_download
        .checked_add(report.bytes.udp_download)
        .context("traffic total exceeds u64")?;
    report.total_bytes = report
        .upload_bytes
        .checked_add(report.download_bytes)
        .context("traffic total exceeds u64")?;
    Ok(report)
}

fn decode_sample(line: &[u8], index: u64) -> Result<Sample> {
    let sample: Sample = serde_json::from_slice(line)
        .map_err(|_| anyhow::anyhow!("invalid traffic record {index}"))?;
    if sample.version != 1 {
        bail!("unsupported traffic format at record {index}");
    }
    Ok(sample)
}

/// Unix seconds, explicit Z/offset timestamps, or wall-clock time in the process timezone.
pub fn parse_time(value: &str) -> Result<u64> {
    if value.bytes().all(|b| b.is_ascii_digit()) && !value.is_empty() {
        return value.parse().context("invalid Unix timestamp");
    }
    let bytes = value.as_bytes();
    if bytes.len() < 16
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b' ')
        || bytes[13] != b':'
    {
        bail!("timestamp must be Unix seconds or YYYY-MM-DDTHH:MM[:SS][Z|+HH:MM|-HH:MM]");
    }
    let number = |start: usize, end: usize| -> Result<i64> {
        let part = &bytes[start..end];
        if !part.iter().all(u8::is_ascii_digit) {
            bail!("invalid timestamp digits");
        }
        Ok(part
            .iter()
            .fold(0, |n, byte| n * 10 + i64::from(byte - b'0')))
    };
    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let (second, end) = if bytes.get(16) == Some(&b':') {
        if bytes.len() < 19 {
            bail!("incomplete timestamp seconds");
        }
        (number(17, 19)?, 19)
    } else {
        (0, 16)
    };
    let offset = match &bytes[end..] {
        [] => None,
        [b'Z'] => Some(0),
        [sign @ (b'+' | b'-'), _, _, b':', _, _] => {
            let hour = number(end + 1, end + 3)?;
            let minute = number(end + 4, end + 6)?;
            if hour > 23 || minute > 59 {
                bail!("invalid timezone offset");
            }
            // RFC3339 -00:00 means the local offset is unknown, not UTC.
            if *sign == b'-' && hour == 0 && minute == 0 {
                bail!("unknown -00:00 offset; use Z or +00:00");
            }
            Some((hour * 3600 + minute * 60) * if *sign == b'-' { -1 } else { 1 })
        }
        _ => bail!("invalid timestamp timezone suffix"),
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        _ => 0,
    };
    if year < 1970 || day < 1 || day > days || hour > 23 || minute > 59 || second > 59 {
        bail!("invalid calendar timestamp");
    }
    if offset.is_none() {
        return local_timestamp(year, month, day, hour, minute, second);
    }
    let y = year - i64::from(month <= 2);
    let era = y / 400;
    let yoe = y - era * 400;
    let m = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let timestamp = (era * 146097 + doe - 719468) * 86400 + hour * 3600 + minute * 60 + second
        - offset.unwrap();
    timestamp
        .try_into()
        .context("timestamp precedes Unix epoch")
}

fn initialize_local_timezone() {
    unsafe extern "C" {
        fn tzset();
    }
    static INITIALIZED: std::sync::Once = std::sync::Once::new();
    // POSIX does not require localtime_r to initialize timezone state itself.
    // TZ is fixed at process startup; never mutate the environment from worker threads.
    INITIALIZED.call_once(|| unsafe { tzset() });
}

fn local_parts(timestamp: libc::time_t) -> Result<libc::tm> {
    initialize_local_timezone();
    let mut parts = std::mem::MaybeUninit::<libc::tm>::uninit();
    // localtime_r writes the entire tm on success; TZ (or the system zone) is handled by libc.
    if unsafe { libc::localtime_r(&timestamp, parts.as_mut_ptr()) }.is_null() {
        bail!("local timestamp is outside the platform range");
    }
    Ok(unsafe { parts.assume_init() })
}

fn local_timestamp(
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
) -> Result<u64> {
    initialize_local_timezone();
    let mut candidates = Vec::new();
    // Check automatic, standard and daylight mappings by round-trip. mktime alone
    // silently normalizes gaps and chooses one side of a repeated DST hour.
    for isdst in [-1, 0, 1] {
        let mut parts: libc::tm = unsafe { std::mem::zeroed() };
        parts.tm_year = (year - 1900) as i32;
        parts.tm_mon = (month - 1) as i32;
        parts.tm_mday = day as i32;
        parts.tm_hour = hour as i32;
        parts.tm_min = minute as i32;
        parts.tm_sec = second as i32;
        parts.tm_isdst = isdst;
        let timestamp = unsafe { libc::mktime(&mut parts) };
        if timestamp < 0 {
            continue;
        }
        let round_trip = local_parts(timestamp)?;
        if round_trip.tm_year == (year - 1900) as i32
            && round_trip.tm_mon == (month - 1) as i32
            && round_trip.tm_mday == day as i32
            && round_trip.tm_hour == hour as i32
            && round_trip.tm_min == minute as i32
            && round_trip.tm_sec == second as i32
            && !candidates.contains(&timestamp)
        {
            candidates.push(timestamp);
        }
    }
    match candidates.as_slice() {
        [timestamp] => Ok(*timestamp as u64),
        [] => bail!(
            "local time does not exist or is outside the platform range; specify Z or an explicit offset"
        ),
        _ => {
            bail!("ambiguous local time at a timezone transition; specify Z or an explicit offset")
        }
    }
}

/// Human-readable process-local time, including its UTC offset at this instant.
pub fn format_local_time(timestamp: u64) -> Result<String> {
    let timestamp = timestamp
        .try_into()
        .context("timestamp exceeds platform time range")?;
    let parts = local_parts(timestamp)?;
    let offset = parts.tm_gmtoff;
    let magnitude = offset.unsigned_abs();
    let mut suffix = format!(
        "{}{:02}:{:02}",
        if offset < 0 { '-' } else { '+' },
        magnitude / 3600,
        magnitude % 3600 / 60
    );
    if magnitude % 60 != 0 {
        suffix.push_str(&format!(":{:02}", magnitude % 60));
    }
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{suffix}",
        i64::from(parts.tm_year) + 1900,
        parts.tm_mon + 1,
        parts.tm_mday,
        parts.tm_hour,
        parts.tm_min,
        parts.tm_sec
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn sample(timestamp: u64, upload: u64, download: u64) -> Sample {
        Sample {
            version: 1,
            timestamp,
            since: timestamp.saturating_sub(60),
            bytes: Bytes {
                tcp_upload: upload,
                tcp_download: download,
                udp_upload: 3,
                udp_download: 7,
            },
        }
    }

    #[test]
    fn journal_survives_restart_and_query_uses_half_open_sample_times() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("traffic.jsonl");
        {
            let mut journal = Journal::open(&path).unwrap();
            journal.append(&sample(60, 10, 20)).unwrap();
            journal.append(&sample(120, 30, 40)).unwrap();
            // Query is allowed while the recorder holds its lifetime writer lock.
            assert_eq!(query(&path, None, None).unwrap().samples, 2);
            assert!(Journal::open(&path).is_err());
        }
        let mut journal = Journal::open(&path).unwrap();
        journal.append(&sample(180, 50, 60)).unwrap();
        let all = query(&path, None, None).unwrap();
        assert_eq!(all.upload_bytes, 99);
        assert_eq!(all.download_bytes, 141);
        assert_eq!(all.total_bytes, 240);
        assert_eq!(all.samples, 3);
        let range = query(&path, Some(120), Some(180)).unwrap();
        assert_eq!(range.samples, 1);
        assert_eq!(range.bytes, sample(120, 30, 40).bytes);
        assert_eq!(query(&path, Some(181), None).unwrap().total_bytes, 0);
        assert!(query(&path, Some(120), Some(120)).is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    }

    #[test]
    fn torn_tail_is_ignored_then_recovered_without_discarding_complete_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("traffic.jsonl");
        let mut journal = Journal::open(&path).unwrap();
        journal.append(&sample(60, 10, 20)).unwrap();
        drop(journal);
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"{\"version\":1")
            .unwrap();
        let report = query(&path, None, None).unwrap();
        assert!(report.incomplete_tail_ignored);
        assert_eq!(report.samples, 1);
        let mut journal = Journal::open(&path).unwrap();
        journal.append(&sample(120, 1, 2)).unwrap();
        drop(journal);
        assert_eq!(query(&path, None, None).unwrap().samples, 2);
        assert!(!query(&path, None, None).unwrap().incomplete_tail_ignored);
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"not JSON\n")
            .unwrap();
        let error = query(&path, None, None).unwrap_err();
        assert!(error.to_string().contains("record 3"));
        let length = std::fs::metadata(&path).unwrap().len();
        assert!(Journal::open(&path).is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), length);
    }

    #[test]
    fn sampler_retries_without_losing_or_double_counting_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("traffic.jsonl");
        let mut journal = Journal::open(&path).unwrap();
        let counters = Counters::default();
        let mut sampler = Sampler {
            previous: Bytes::default(),
            since: 0,
        };
        counters.values[0].store(100, Ordering::Relaxed);
        sampler.flush(&mut journal, &counters, 60).unwrap();
        counters.values[0].store(250, Ordering::Relaxed);
        journal.poisoned = true; // Simulate persistent IO failure.
        assert!(sampler.flush(&mut journal, &counters, 120).is_err());
        assert_eq!(sampler.since, 60);
        assert_eq!(sampler.previous.tcp_upload, 100);
        journal.poisoned = false;
        counters.values[0].store(400, Ordering::Relaxed);
        sampler.flush(&mut journal, &counters, 180).unwrap();
        sampler.flush(&mut journal, &counters, 181).unwrap();
        let all = query(&path, None, None).unwrap();
        assert_eq!(all.upload_bytes, 400);
        assert_eq!(all.samples, 3);
        assert_eq!(all.extended_windows, 1);
    }

    #[test]
    fn worker_flushes_all_four_counters_on_stop_without_waiting_a_minute() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("traffic.jsonl");
        let journal = Journal::open(&path).unwrap();
        let counters = Arc::new(Counters::default());
        for (index, counter) in counters.values.iter().enumerate() {
            counter.store((index + 1) as u64, Ordering::Relaxed);
        }
        let (sender, stop) = mpsc::channel();
        sender.send(()).unwrap();
        collect(journal, counters, stop).unwrap();
        let all = query(&path, None, None).unwrap();
        assert_eq!(
            all.bytes,
            Bytes {
                tcp_upload: 1,
                tcp_download: 2,
                udp_upload: 3,
                udp_download: 4
            }
        );
        assert_eq!(all.total_bytes, 10);
    }

    #[test]
    fn private_permissions_symlinks_and_nonregular_files_are_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("traffic.jsonl");
        drop(Journal::open(&path).unwrap());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Journal::open(&path).is_err());
        assert!(query(&path, None, None).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let alias = dir.path().join("alias");
        symlink(&path, &alias).unwrap();
        assert!(Journal::open(&alias).is_err());
        assert!(query(&alias, None, None).is_err());
        assert!(query(dir.path(), None, None).is_err());
        std::fs::write(&path, b"token=must-not-be-overwritten").unwrap();
        assert!(Journal::open(&path).is_err());
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"token=must-not-be-overwritten"
        );
    }

    #[test]
    fn invalid_versions_oversized_records_and_overflow_fail_explicitly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("traffic.jsonl");
        let mut journal = Journal::open(&path).unwrap();
        journal.append(&sample(60, u64::MAX, 0)).unwrap();
        assert!(query(&path, None, None).is_err()); // TCP + UDP overflow.
        drop(journal);
        std::fs::write(&path, b"{\"version\":2,\"timestamp\":0,\"since\":0,\"bytes\":{\"tcp_upload\":0,\"tcp_download\":0,\"udp_upload\":0,\"udp_download\":0}}\n").unwrap();
        assert!(
            query(&path, None, None)
                .unwrap_err()
                .to_string()
                .contains("unsupported")
        );
        std::fs::write(&path, vec![b'x'; MAX_LINE + 1]).unwrap();
        assert!(query(&path, None, None).is_err());
        assert!(Journal::open(&path).is_err());
    }

    #[test]
    fn timestamps_validate_calendar_and_respect_explicit_offsets() {
        assert_eq!(parse_time("1970-01-01T00:00Z").unwrap(), 0);
        assert_eq!(parse_time("2000-02-29T12:34:56Z").unwrap(), 951827696);
        assert_eq!(parse_time("2026-10-06T00:00Z").unwrap(), 1791244800);
        assert_eq!(parse_time("1791244800").unwrap(), 1791244800);
        assert_eq!(parse_time("2026-10-06T08:00+08:00").unwrap(), 1791244800);
        assert_eq!(parse_time("2026-10-05T20:00:00-04:00").unwrap(), 1791244800);
        assert_eq!(parse_time("2026-10-06 05:30+05:30").unwrap(), 1791244800);
        assert_eq!(parse_time("2026-10-06T00:00+00:00").unwrap(), 1791244800);
        for bad in [
            "",
            "-1",
            "2026-02-29T00:00Z",
            "2100-02-29T00:00Z",
            "2026-00-01T00:00Z",
            "2026-01-00T00:00Z",
            "2026-04-31T00:00Z",
            "2026-01-01T24:00Z",
            "2026-01-01T12:60Z",
            "2026-01-01T12:00:60Z",
            "2026-01-01T12:00+24:00",
            "2026-01-01T12:00+08:60",
            "2026-01-01T12:00+0800",
            "2026-01-01T12:00-00:00",
            "2026-01-01T12:00:Z",
            "2026-01-01T12:00:00Zextra",
            "1970-01-01T00:00+08:00",
            "1969-12-31T23:59Z",
        ] {
            assert!(parse_time(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn clock_reversal_is_reported_without_discarding_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("traffic.jsonl");
        let mut journal = Journal::open(&path).unwrap();
        let mut row = sample(100, 4, 5);
        row.since = 200;
        journal.append(&row).unwrap();
        assert_eq!(query(&path, None, None).unwrap().clock_reversals, 1);
    }
}
