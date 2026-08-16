pub mod api;
pub mod catalog_cache;
pub mod clash;
pub mod cli;
pub mod config;
pub mod gateway;
pub mod http_proxy;
pub mod http_server;
pub mod nodes;
pub mod perftrace;
pub mod rlimit;
pub mod snell;
pub mod socks5;
pub mod surge;
pub mod transport;

pub const APP_NAME: &str = "oixc-proxy";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
