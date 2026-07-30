#[tokio::main]
async fn main() {
    let exit_code = oixc_proxy::cli::run(std::env::args().skip(1).collect()).await;
    std::process::exit(exit_code);
}
