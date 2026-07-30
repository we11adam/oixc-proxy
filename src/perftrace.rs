use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static NEXT_REQUEST: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
struct Trace {
    request: u64,
    started: Instant,
}

tokio::task_local! {
    static CURRENT: Trace;
}

pub async fn scope<F: Future>(future: F) -> F::Output {
    let trace = Trace {
        request: NEXT_REQUEST.fetch_add(1, Ordering::Relaxed) + 1,
        started: Instant::now(),
    };
    CURRENT
        .scope(trace, async move {
            event("socks.accept", &[]);
            future.await
        })
        .await
}

pub fn event(stage: &str, fields: &[(&str, String)]) {
    write(stage, None, fields);
}

pub fn stage(stage: &str, started: Instant, status_ok: bool, fields: &[(&str, String)]) {
    let mut all_fields = fields.to_vec();
    all_fields.push(("status", if status_ok { "ok" } else { "error" }.to_owned()));
    write(stage, Some(started.elapsed()), &all_fields);
}

fn write(stage: &str, step: Option<Duration>, fields: &[(&str, String)]) {
    let _ = CURRENT.try_with(|trace| {
        let mut message = format!("perf request={:06} stage={stage}", trace.request,);
        if let Some(step) = step {
            message.push_str(&format!(" step={}", format_duration(step)));
        }
        message.push_str(&format!(
            " total={}",
            format_duration(trace.started.elapsed())
        ));
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
