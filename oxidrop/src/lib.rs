pub mod api;
pub mod auth;
pub mod db;
pub mod ebpf;
pub mod router;
pub mod state;
use clap::Parser;
#[derive(Debug, Clone, Parser)]
pub struct Opt {
    /// choose http port
    #[clap(short = 'p', long, default_value_t = 3000)]
    pub http_port: u16,
    /// The network interface index for incoming traffic (e.g., 2)
    #[clap(long, short)]
    pub incoming_adapter: Option<u32>,

    /// The network interface index for outgoing traffic (e.g., 3)
    #[clap(long, short)]
    pub output_adapter: Option<u32>,
}
