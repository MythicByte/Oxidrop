pub mod auth;
pub mod router;
use anyhow::Context as _;
use aya::programs::{
    Xdp,
    XdpMode,
};
use clap::Parser;
use tower_sessions::{
    Expiry,
    MemoryStore,
    SessionManagerLayer,
    cookie::time::Duration,
};
#[rustfmt::skip]
use tracing::{
    Level,
    info,
    warn,
};
use tracing_subscriber::FmtSubscriber;

use crate::router::combined_router;

#[derive(Debug, Parser)]
#[command(arg_required_else_help = true)]
struct Opt {
    /// internet interface name
    #[clap(short, long, default_value = "eth0")]
    iface: String,

    /// choose http port
    #[clap(long, default_value_t = 3000)]
    http_port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    // set gloab default
    tracing::subscriber::set_global_default(subscriber)
        .expect("Tracing Subscriber failed to setup");

    info!("Application ist starting");

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/oxidrop"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.expect("eBPF guard failed");
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let Opt { iface, http_port } = opt;
    let program: &mut Xdp = ebpf
        .program_mut("oxidrop")
        .expect("Getting the eBPF failed")
        .try_into()?;
    program.load()?;
    program.attach(&iface, XdpMode::default())
        .context("failed to attach the XDP program with default mode - try changing XdpMode::default() to XdpMode::Skb")?;
    info!("XDP program attached to {}", &iface);

    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(cfg!(not(debug_assertions))) // secure in debug off
        .with_expiry(Expiry::OnInactivity(Duration::minutes(10)));

    let app = combined_router().layer(session_layer);
    let addr = format!("127.0.0.1:{}", http_port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Listener for axum failed to setup");
    info!("Server running on port {http_port}");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to listen for ctrl-c");
            info!("Ctrl-C received, starting graceful shutdown...");
        })
        .await
        .expect("Axum failed");

    Ok(())
}
