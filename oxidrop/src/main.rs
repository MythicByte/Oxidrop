pub mod router;
pub mod auth;
use anyhow::Context as _;
use axum::{Router, routing::get};
use aya::programs::{Xdp, XdpMode};
use clap::Parser;
use tokio::net::UnixListener;
#[rustfmt::skip]
use tokio::signal;
use tracing::{Level, info, warn};
use tracing_subscriber::FmtSubscriber;
use hyper::server::conn::http1;
use hyper_util::{rt::TokioIo, service::TowerToHyperService};


#[derive(Debug, Parser)]
struct Opt {
    /// interface name
    #[clap(short, long, default_value = "eth0")]
    iface: String,

    /// Path for the Unix socket (e.g., /tmp/oxidrop.sock)
    #[clap(long, default_value = "/tmp/oxidrop.sock")]
    socket_path: String,
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
    let Opt { iface,socket_path } = opt;
    let program: &mut Xdp = ebpf.program_mut("oxidrop").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpMode::default())
        .context("failed to attach the XDP program with default mode - try changing XdpMode::default() to XdpMode::Skb")?;
    info!("XDP program attached to {}", &iface);

        let app = Router::new()
        .route("/", get(|| async { "Oxidrop eBPF is running\n" }));
        let socket_path = socket_path.clone();
    // Remove old socket file if it exists (safety check omitted for brevity)
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path)?;
    info!("Axum server listening on {}", socket_path);
        // Spawn the HTTP server as a background task
        let server_task = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let app = app.clone();
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        // Wrap `app` with TowerToHyperService::new(...)
                        if let Err(err) = http1::Builder::new()
                            .serve_connection(io, TowerToHyperService::new(app))
                            .await
                        {
                            warn!("Connection error: {:?}", err);
                        }
                    });
                }
                Err(e) => {
                    warn!("Accept error: {e}");
                }
            }
        }
    });





    let ctrl_c = signal::ctrl_c();
    info!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    server_task.abort();
    info!("Exiting...");

    Ok(())
}

