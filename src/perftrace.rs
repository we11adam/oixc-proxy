use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static NEXT_REQUEST: AtomicU64 = AtomicU64::new(0);
static SAMPLE_EVERY: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
struct Trace {
    request: u64,
    started: Instant,
}

tokio::task_local! {
    static CURRENT: Trace;
}

pub async fn scope<F: Future>(future: F) -> F::Output {
    let sample_every = SAMPLE_EVERY.load(Ordering::Relaxed);
    if sample_every == 0 {
        return future.await;
    }
    let request = NEXT_REQUEST.fetch_add(1, Ordering::Relaxed) + 1;
    if !should_sample(request, sample_every) {
        return future.await;
    }
    let trace = Trace {
        request,
        started: Instant::now(),
    };
    CURRENT
        .scope(trace, async move {
            event("socks.accept", &[]);
            future.await
        })
        .await
}

pub fn configure(sample_every: usize) {
    SAMPLE_EVERY.store(sample_every as u64, Ordering::Relaxed);
}

pub fn enabled() -> bool {
    CURRENT.try_with(|_| ()).is_ok()
}

pub fn event(stage: &str, fields: &[(&str, String)]) {
    write(stage, None, None, fields);
}

pub fn stage(stage: &str, started: Instant, status_ok: bool, fields: &[(&str, String)]) {
    write(stage, Some(started.elapsed()), Some(status_ok), fields);
}

fn write(stage: &str, step: Option<Duration>, status_ok: Option<bool>, fields: &[(&str, String)]) {
    let _ = CURRENT.try_with(|trace| {
        let mut message = format!("perf request={:06} stage={stage}", trace.request,);
        if let Some(step) = step {
            message.push_str(&format!(" step={}", format_duration(step)));
        }
        message.push_str(&format!(
            " total={}",
            format_duration(trace.started.elapsed())
        ));
        if let Some(status_ok) = status_ok {
            message.push_str(if status_ok {
                " status=ok"
            } else {
                " status=error"
            });
        }
        for (key, value) in fields {
            if key.is_empty() {
                continue;
            }
            message.push(' ');
            message.push_str(key);
            message.push('=');
            message.push_str(&value.replace(['\r', '\n'], " "));
        }
        eprintln!("{message}");
    });
}

fn should_sample(request: u64, sample_every: u64) -> bool {
    request.saturating_sub(1) % sample_every == 0
}

fn format_duration(duration: Duration) -> String {
    let micros = duration.as_micros();
    if micros >= 1_000_000 {
        format!("{:.6}s", micros as f64 / 1_000_000.0)
    } else if micros >= 1_000 {
        format!("{:.3}ms", micros as f64 / 1_000.0)
    } else {
        format!("{micros}µs")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_first_request_and_then_at_interval() {
        assert!(should_sample(1, 100));
        assert!(!should_sample(2, 100));
        assert!(should_sample(101, 100));
    }
}
