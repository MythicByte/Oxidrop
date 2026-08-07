pub mod auth;
pub mod router;
use anyhow::Context as _;
use axum::{
    Router,
    routing::get,
};
use aya::programs::{
    Xdp,
    XdpMode,
};
use clap::Parser;
#[rustfmt::skip]
use tracing::{
    Level,
    info,
    warn,
};
use tracing_subscriber::FmtSubscriber;

#[derive(Debug, Parser)]
struct Opt {
    /// interface name
    #[clap(short, long, default_value = "eth0")]
    iface: String,

    #[clap(short, long, default_value_t = 3000)]
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
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let Opt { iface, http_port } = opt;
    let program: &mut Xdp = ebpf.program_mut("oxidrop").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpMode::default())
        .context("failed to attach the XDP program with default mode - try changing XdpMode::default() to XdpMode::Skb")?;
    info!("XDP program attached to {}", &iface);

    let app = Router::new().route("/", get(|| async { "Oxidrop eBPF is running\n" }));
    let addr = format!("127.0.0.1:{}", http_port);
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    info!("Server running on port {http_port}");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to listen for ctrl-c");
            info!("Ctrl-C received, starting graceful shutdown...");
        })
        .await
        .unwrap();

    Ok(())
}
