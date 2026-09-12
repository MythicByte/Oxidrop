use std::{
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use axum_login::AuthManagerLayerBuilder;
use aya::maps::lpm_trie::Key;
use clap::Parser;
use hyper::StatusCode;
use oxidrop::{
    Opt,
    db::{
        self,
    },
    ebpf::EbpfProgramm,
    router::combined_router,
    state::{
        FirewallState,
        LogStore,
    },
};
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
    SessionManagerLayer,
    cookie::SameSite,
};
use tower_sessions_redis_store::{
    RedisStore,
    fred::{
        clients::Pool,
        interfaces::ClientLike,
        types::config::Config,
    },
};
use tracing::error;
#[rustfmt::skip] use tracing::{
    Level,
    info,
};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    let http_port = opt.http_port;

    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .context("Tracing Subscriber failed to setup")?;

    info!("Application ist starting");

    let mut ebpf_programm = EbpfProgramm::new()?;
    let (
        mut config_map,
        allow_list_v4,
        allow_list_v6,
        packet_counts_v4,
        packet_counts_v6,
        mut subnet_matching_v4,
        mut subnet_matching_v6,
    ) = ebpf_programm.get_maps()?;

    let db = db::Database::new("sqlite://oxidrop.db").await?;
    db.bootstrap_default_admin()
        .await
        .context("Failed to bootstrap the default admin user")?;
    for (network, prefix_len, action) in db.list_subnet_v4().await? {
        subnet_matching_v4
            .insert(&Key::new(prefix_len, network.to_be()), action, 0)
            .context("Failed to restore IPv4 subnet rule")?;
    }
    for (network, prefix_len, action) in db.list_subnet_v6().await? {
        subnet_matching_v6
            .insert(&Key::new(prefix_len, network.map(u32::to_be)), action, 0)
            .context("Failed to restore IPv6 subnet rule")?;
    }
    let persisted_firewall_config = db.load_firewall_config().await?;
    let mut firewall_config = persisted_firewall_config.unwrap_or_default();
    if persisted_firewall_config.is_none() {
        firewall_config.incoming_ethernet_adapter = opt.incoming_adapter;
        firewall_config.output_ethernet_adapter = opt.output_adapter;
    }
    config_map
        .set(0, firewall_config, 0)
        .context("Failed to load persisted firewall configuration into CONFIG map")?;
    if let Err(e) = ebpf_programm.reboot(&firewall_config, &opt) {
        error!("Failed to attach XDP programs on startup: {}", e);
    }
    db.save_firewall_config(&firewall_config)
        .await
        .context("Failed to persist firewall configuration")?;

    let state = FirewallState {
        db: db.clone(),
        config: Arc::new(RwLock::new(config_map)),
        allow_list_v4: Arc::new(RwLock::new(allow_list_v4)),
        allow_list_v6: Arc::new(RwLock::new(allow_list_v6)),
        packet_counts_v4: Arc::new(RwLock::new(packet_counts_v4)),
        packet_counts_v6: Arc::new(RwLock::new(packet_counts_v6)),
        subnet_matching_v4: Arc::new(RwLock::new(subnet_matching_v4)),
        subnet_matching_v6: Arc::new(RwLock::new(subnet_matching_v6)),
        logs: Arc::new(LogStore::new(db.clone())),
        ebpf: Some(Arc::new(tokio::sync::Mutex::new(ebpf_programm))),
        opt: opt.clone(),
    };
    state
        .logs
        .record("INFO", "Application started", Some("system"))
        .await;
    let state_clone = state.clone();
    spawn_cleanup_connection_map_after_10_minutes(state_clone);

    let session_layer = session_store_build().await?;
    let auth_layer = AuthManagerLayerBuilder::new(state.db.clone(), session_layer).build();

    let logs = state.logs.clone();
    let app = combined_router(state)
        .layer(
            ServiceBuilder::new()
                .layer(CatchPanicLayer::new())
                .layer(
                    TraceLayer::new_for_http()
                        .make_span_with(|request: &axum::http::Request<_>| {
                            let client_ip = request
                                .extensions()
                                .get::<axum::extract::ConnectInfo<SocketAddr>>()
                                .map(|info| info.0.ip().to_string())
                                .unwrap_or_else(|| "unknown".to_string());
                            tracing::info_span!(
                                "http_request",
                                method = %request.method(),
                                uri = %request.uri(),
                                client_ip = %client_ip,
                            )
                        })
                        .on_failure(
                            |error: tower_http::classify::ServerErrorsFailureClass,
                             latency: Duration,
                             span: &tracing::Span| {
                                tracing::error!(
                                    parent: span,
                                    error = %error,
                                    latency_ms = latency.as_millis(),
                                    "request failed",
                                );
                            },
                        ),
                )
                .layer(TimeoutLayer::with_status_code(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Duration::from_secs(30),
                ))
                .layer(RequestBodyLimitLayer::new(1024 * 1024 * 5)) // 5MB
                .layer(CompressionLayer::new())
                .layer(
                    CorsLayer::new()
                        // Explicitly list your frontend development origins
                        .allow_origin([
                            "http://127.0.0.1:5173"
                                .parse::<axum::http::HeaderValue>()
                                .unwrap(),
                            "http://localhost:5173"
                                .parse::<axum::http::HeaderValue>()
                                .unwrap(),
                        ])
                        .allow_methods([
                            axum::http::Method::GET,
                            axum::http::Method::POST,
                            axum::http::Method::PUT,
                            axum::http::Method::DELETE,
                            axum::http::Method::OPTIONS,
                        ])
                        .allow_headers([
                            axum::http::header::CONTENT_TYPE,
                            axum::http::header::AUTHORIZATION,
                            axum::http::header::ACCEPT,
                        ])
                        .allow_credentials(true)
                        .max_age(Duration::from_hours(1)),
                ),
        )
        .layer(auth_layer);
    let addr = format!("127.0.0.1:{}", http_port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .context("Listener for axum failed to setup")?;
    info!("Server running on port {http_port}");
    logs.record(
        "INFO",
        &format!("Server listening on port {http_port}"),
        Some("system"),
    )
    .await;

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
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
                    if let Ok((key, state_val)) = entry
                        && current_bpf_time.saturating_sub(state_val.last_seen) > TIMEOUT_NS
                    {
                        keys_to_remove.push(key);
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
                    if let Ok((key, state_val)) = entry
                        && current_bpf_time.saturating_sub(state_val.last_seen) > TIMEOUT_NS
                    {
                        v6_keys_to_remove.push(key);
                    }
                }
                for key in v6_keys_to_remove {
                    let _ = v6_map.remove(&key);
                }
            }
        }
    });
}
async fn session_store_build() -> anyhow::Result<SessionManagerLayer<RedisStore<Pool>>> {
    let pool = Pool::new(Config::default(), None, None, None, 6)?;

    let _redis_conn = pool.connect();
    pool.wait_for_connect().await.context(
        "could not connect to redis \nIs it started yet ? \nExecute: sudo systemctl start redis",
    )?;

    // Spawn the background cleanup task
    let session_store = RedisStore::new(pool);
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(cfg!(not(debug_assertions))) // secure in debug off
        .with_expiry(Expiry::OnInactivity(
            tower_sessions::cookie::time::Duration::minutes(10),
        ))
        .with_http_only(true)
        .with_same_site(SameSite::Strict);
    // .with_name("__Host-session");
    Ok(session_layer)
}
