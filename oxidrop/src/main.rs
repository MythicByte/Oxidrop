pub mod api;
pub mod auth;
pub mod db;
pub mod ebpf;
pub mod router;
pub mod state;
use std::{
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use clap::Parser;
use hyper::StatusCode;
use oxidrop_common::FirewallConfig;
use rustix::time::{
    ClockId,
    clock_gettime,
};
use tokio::sync::RwLock;
use tower::ServiceBuilder;
use tower_http::{
    catch_panic::CatchPanicLayer,
    compression::CompressionLayer,
    cors::CorsLayer,
    limit::RequestBodyLimitLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tower_sessions::{
    Expiry,
    MemoryStore,
    SessionManagerLayer,
    cookie::SameSite,
};
use tracing::error;
#[rustfmt::skip] use tracing::{
    Level,
    info,
};
use tracing_subscriber::FmtSubscriber;

use crate::{
    db::Database,
    ebpf::EbpfProgramm,
    router::combined_router,
    state::FirewallState,
};

#[derive(Debug, Parser)]
pub struct Opt {
    /// choose http port
    #[clap(long, default_value_t = 3000)]
    http_port: u16,
    /// The network interface index for incoming traffic (e.g., 2)
    #[clap(long, short)]
    incoming_adapter: Option<u32>,

    /// The network interface index for outgoing traffic (e.g., 3)
    #[clap(long, short)]
    output_adapter: Option<u32>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    let Opt { http_port, .. } = opt;

    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .context("Tracing Subscriber failed to setup")?;

    info!("Application ist starting");

    let mut ebpf_programm = EbpfProgramm::new()?;
    ebpf_programm.reboot(&FirewallConfig::default(), &opt)?;
    let (
        config_map,
        allow_list_v4,
        allow_list_v6,
        packet_counts_v4,
        packet_counts_v6,
        subnet_matching_v4,
        subnet_matching_v6,
    ) = ebpf_programm.get_maps()?;

    let db = db::Database::new("sqlite://oxidrop.db").await?;

    let db_cloned = db.clone();
    spawn_db_default_user(db_cloned);

    let state = FirewallState {
        db,
        config: Arc::new(RwLock::new(config_map)),
        allow_list_v4: Arc::new(RwLock::new(allow_list_v4)),
        allow_list_v6: Arc::new(RwLock::new(allow_list_v6)),
        packet_counts_v4: Arc::new(RwLock::new(packet_counts_v4)),
        packet_counts_v6: Arc::new(RwLock::new(packet_counts_v6)),
        subnet_matching_v4: Arc::new(RwLock::new(subnet_matching_v4)),
        subnet_matching_v6: Arc::new(RwLock::new(subnet_matching_v6)),
    };
    let state_clone = state.clone();
    spawn_cleanup_connection_map_after_10_minutes(state_clone);
    // Spawn the background cleanup task
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(cfg!(not(debug_assertions))) // secure in debug off
        .with_expiry(Expiry::OnInactivity(
            tower_sessions::cookie::time::Duration::minutes(10),
        ))
        .with_http_only(true)
        .with_same_site(SameSite::Strict)
        .with_name("__Host-session");

    let app = combined_router(state)
        .layer(
            ServiceBuilder::new()
                .layer(CatchPanicLayer::new())
                .layer(TraceLayer::new_for_http())
                .layer(TimeoutLayer::with_status_code(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Duration::from_secs(30),
                ))
                .layer(RequestBodyLimitLayer::new(1024 * 1024 * 5)) // 5MB
                .layer(CompressionLayer::new())
                .layer(CorsLayer::permissive().max_age(Duration::from_hours(1))),
        )
        .layer(session_layer);
    let addr = format!("127.0.0.1:{}", http_port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .context("Listener for axum failed to setup")?;
    info!("Server running on port {http_port}");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            if let Err(err) = tokio::signal::ctrl_c().await {
                error!("Failed to listen for shutdown signal: {err}");
            }
            info!("Shutdown signal received, shutting down gracefully...");
        })
        .await
        .context("Axum serving failed")?;

    Ok(())
}
fn get_bpf_ktime_ns() -> u64 {
    let ts = clock_gettime(ClockId::Monotonic);
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}
fn spawn_db_default_user(db: Database) {
    tokio::spawn(async move {
        if let Err(e) = db.bootstrap_default_admin().await {
            error!("Failed to bootstrap default admin: {}", e);
        }
    });
}
/// cleanup old connection after 10 Minutes
fn spawn_cleanup_connection_map_after_10_minutes(state: FirewallState) {
    tokio::spawn(async move {
        const TIMEOUT_NS: u64 = 10 * 60 * 1_000_000_000; // 10 minutes
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(600));

        loop {
            interval.tick().await;
            let current_bpf_time = get_bpf_ktime_ns();

            // Clean up IPv4 allow list
            {
                let mut v4_map = state.allow_list_v4.write().await;
                let mut keys_to_remove = Vec::new();
                for entry in v4_map.iter() {
                    if let Ok((key, state_val)) = entry {
                        if current_bpf_time.saturating_sub(state_val.last_seen) > TIMEOUT_NS {
                            keys_to_remove.push(key);
                        }
                    }
                }
                for key in keys_to_remove {
                    let _ = v4_map.remove(&key);
                }
            }

            // Clean up IPv6 allow list
            {
                let mut v6_map = state.allow_list_v6.write().await;
                let mut v6_keys_to_remove = Vec::new();
                for entry in v6_map.iter() {
                    if let Ok((key, state_val)) = entry {
                        if current_bpf_time.saturating_sub(state_val.last_seen) > TIMEOUT_NS {
                            v6_keys_to_remove.push(key);
                        }
                    }
                }
                for key in v6_keys_to_remove {
                    let _ = v6_map.remove(&key);
                }
            }
        }
    });
}
