#[cfg(not(windows))]
#[tokio::main]
async fn main() {
    let exit_code = oixc_proxy::cli::run(std::env::args().skip(1).collect()).await;
    std::process::exit(exit_code);
}

#[cfg(windows)]
fn main() {
    if std::env::args().nth(1).as_deref() == Some("windows-service") {
        if let Err(error) = oixc_proxy::windows::service::dispatch() {
            eprintln!("error: {error:#}");
            std::process::exit(1);
        }
        return;
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("create async runtime");
    let exit_code = runtime.block_on(oixc_proxy::cli::run(std::env::args().skip(1).collect()));
    runtime.shutdown_timeout(std::time::Duration::from_secs(5));
    std::process::exit(exit_code);
}
