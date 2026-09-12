use std::{
    fs,
    sync::Arc,
};

use axum::{
    Json,
    Router,
    extract::{
        State,
        ws::{
            Message,
            WebSocket,
            WebSocketUpgrade,
        },
    },
    response::IntoResponse,
    routing::{
        get,
        post,
    },
};
use axum_login::AuthSession;
use aya::maps::{
    Array,
    HashMap,
    LpmTrie,
    MapData,
    lpm_trie::Key,
};
use hyper::StatusCode;
use oxidrop_common::{
    Action,
    ActivaterEtherTypes,
    AllowListState,
    FirewallConfig,
    Ipv4Packet,
    Ipv6Packet,
    RateProfile,
    TokenBucketState,
};
use serde::{
    Deserialize,
    Serialize,
};
use sqlx::FromRow;
use tokio::sync::{
    Mutex,
    RwLock,
    broadcast,
};
use utoipa::ToSchema;

use crate::{
    Opt,
    db::{
        ActionPermissions,
        CallerContext,
        Database,
        RolesUser,
    },
    ebpf::{
        EbpfProgramm,
        get_ebpf_adapters,
    },
};

/// Firewall internal state
#[derive(Clone)]
pub struct FirewallState {
    pub db: Database,
    pub config: Arc<RwLock<Array<MapData, FirewallConfig>>>,
    pub allow_list_v4: Arc<RwLock<HashMap<MapData, Ipv4Packet, AllowListState>>>,
    pub allow_list_v6: Arc<RwLock<HashMap<MapData, Ipv6Packet, AllowListState>>>,
    pub packet_counts_v4: Arc<RwLock<HashMap<MapData, Ipv4Packet, TokenBucketState>>>,
    pub packet_counts_v6: Arc<RwLock<HashMap<MapData, Ipv6Packet, TokenBucketState>>>,
    pub subnet_matching_v4: Arc<RwLock<LpmTrie<MapData, u32, Action>>>,
    pub subnet_matching_v6: Arc<RwLock<LpmTrie<MapData, [u32; 4], Action>>>,
    pub logs: Arc<LogStore>,
    pub ebpf: Option<Arc<Mutex<EbpfProgramm>>>,
    pub opt: Opt,
}

#[derive(Debug, Clone, Serialize, FromRow, ToSchema)]
pub struct LogEntry {
    pub id: i64,
    pub timestamp: i64,
    pub level: String,
    pub message: String,
    pub actor: Option<String>,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub source_port: Option<i64>,
    pub destination_port: Option<i64>,
    pub protocol: Option<String>,
    pub action: Option<String>,
}

#[derive(Clone)]
pub struct LogStore {
    db: Database,
    tx: broadcast::Sender<LogEntry>,
}

impl LogStore {
    #[must_use]
    pub fn new(db: Database) -> Self {
        let (tx, _) = broadcast::channel(256);
        Self { db, tx }
    }

    pub async fn record(&self, level: &str, message: &str, actor: Option<&str>) {
        self.record_details(level, message, actor, None, None, None, None, None, None)
            .await;
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn record_details(
        &self,
        level: &str,
        message: &str,
        actor: Option<&str>,
        source_ip: Option<&str>,
        destination_ip: Option<&str>,
        source_port: Option<u16>,
        destination_port: Option<u16>,
        protocol: Option<&str>,
        action: Option<&str>,
    ) {
        let result = sqlx::query_as::<_, LogEntry>(
            "INSERT INTO firewall_logs (
                timestamp, level, message, actor, source_ip, destination_ip,
                source_port, destination_port, protocol, action
             ) VALUES (unixepoch(), ?, ?, ?, ?, ?, ?, ?, ?, ?)
             RETURNING id, timestamp, level, message, actor, source_ip,
                       destination_ip, source_port, destination_port, protocol, action",
        )
        .bind(level)
        .bind(message)
        .bind(actor)
        .bind(source_ip)
        .bind(destination_ip)
        .bind(source_port.map(i64::from))
        .bind(destination_port.map(i64::from))
        .bind(protocol)
        .bind(action)
        .fetch_one(&self.db.pool)
        .await;

        match result {
            Ok(entry) => {
                let _ = self.tx.send(entry);
            }

            Err(error) => tracing::error!("failed to persist firewall log: {error}"),
        }
    }

    async fn recent(&self) -> Result<Vec<LogEntry>, sqlx::Error> {
        sqlx::query_as(
            "SELECT id, timestamp, level, message, actor, source_ip, destination_ip,
                    source_port, destination_port, protocol, action
             FROM firewall_logs
             ORDER BY timestamp DESC, id DESC
             LIMIT 500",
        )
        .fetch_all(&self.db.pool)
        .await
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TrafficCounters {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TrafficStatsResponse {
    pub incoming: TrafficCounters,
    pub outgoing: TrafficCounters,
}

fn interface_name(index: Option<u32>) -> Result<Option<String>, std::io::Error> {
    let Some(index) = index else {
        return Ok(None);
    };
    Ok(fs::read_dir("/sys/class/net")?.flatten().find_map(|entry| {
        let name = entry.file_name().into_string().ok()?;
        let ifindex = fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
            .ok()?
            .trim()
            .parse::<u32>()
            .ok()?;
        (ifindex == index).then_some(name)
    }))
}

fn read_interface_counter(interface: &str, counter: &str) -> Result<u64, std::io::Error> {
    let value = fs::read_to_string(format!("/sys/class/net/{interface}/statistics/{counter}"))?;
    value.trim().parse().map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid {counter} counter for {interface}: {error}"),
        )
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/config/traffic",
    responses((status = 200, description = "Interface traffic counters", body = TrafficStatsResponse)),
    security(("cookie_auth" = []))
)]
pub async fn get_traffic_stats(
    State(state): State<FirewallState>,
    auth_session: AuthSession<Database>,
) -> impl IntoResponse {
    if auth_session.user.is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let config = match state.config.read().await.get(&0, 0) {
        Ok(config) => config,
        Err(error) => {
            tracing::error!("failed to read firewall configuration: {error}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let incoming = match interface_name(config.incoming_ethernet_adapter) {
        Ok(interface) => interface,
        Err(error) => {
            tracing::error!("failed to resolve incoming interface: {error}");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let outgoing = match interface_name(config.output_ethernet_adapter) {
        Ok(interface) => interface,
        Err(error) => {
            tracing::error!("failed to resolve outgoing interface: {error}");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    if config.incoming_ethernet_adapter.is_some() && incoming.is_none() {
        tracing::error!("configured incoming interface was not found in sysfs");
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if config.output_ethernet_adapter.is_some() && outgoing.is_none() {
        tracing::error!("configured outgoing interface was not found in sysfs");
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let counters = |interface: Option<String>,
                    packets: &str,
                    bytes: &str|
     -> Result<Option<TrafficCounters>, std::io::Error> {
        interface
            .as_deref()
            .map(|name| {
                Ok(TrafficCounters {
                    packets: read_interface_counter(name, packets)?,
                    bytes: read_interface_counter(name, bytes)?,
                })
            })
            .transpose()
    };
    let incoming = match counters(incoming, "rx_packets", "rx_bytes") {
        Ok(Some(counters)) => counters,
        Ok(None) => TrafficCounters {
            packets: 0,
            bytes: 0,
        },
        Err(error) => {
            tracing::error!("failed to read incoming traffic counters: {error}");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    let outgoing = match counters(outgoing, "tx_packets", "tx_bytes") {
        Ok(Some(counters)) => counters,
        Ok(None) => TrafficCounters {
            packets: 0,
            bytes: 0,
        },
        Err(error) => {
            tracing::error!("failed to read outgoing traffic counters: {error}");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };
    Json(TrafficStatsResponse { incoming, outgoing }).into_response()
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AllowListV4Update {
    pub key: Ipv4Packet,
    pub state: AllowListState,
}
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AllowListV6Update {
    pub key: Ipv6Packet,
    pub state: AllowListState,
}
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PacketCountV4Update {
    pub key: Ipv4Packet,
    pub state: TokenBucketState,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PacketCountV6Update {
    pub key: Ipv6Packet,
    pub state: TokenBucketState,
}
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SubnetMatchV4Update {
    pub network: u32,
    pub prefix_len: u32,
    pub action: Action,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SubnetMatchV6Update {
    pub network: [u32; 4],
    pub prefix_len: u32,
    pub action: Action,
}

// But we need a "patch-style" request type that allows partial updates
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ConfigPatch {
    // All fields optional — only specified fields get updated
    #[serde(default)]
    pub tcp_profile: Option<RateProfile>,
    #[serde(default)]
    pub udp_profile: Option<RateProfile>,
    #[serde(default)]
    pub icmp_profile: Option<RateProfile>,
    #[serde(default)]
    pub default_profile: Option<RateProfile>,
    #[serde(default)]
    #[ schema(value_type = Option<u16>)]
    pub protcol_allowed: Option<ActivaterEtherTypes>,
    #[serde(default)]
    pub ddos_activated: Option<bool>,
    #[serde(default)]
    pub subnet_activated: Option<bool>,
    #[serde(default)]
    pub incoming_ethernet_adapter: Option<Option<u32>>,
    #[serde(default)]
    pub output_ethernet_adapter: Option<Option<u32>>,
}

const MAX_RATE_SHIFT: u64 = 63;

impl ConfigPatch {
    fn validate(&self) -> Result<(), &'static str> {
        let profiles = [
            &self.tcp_profile,
            &self.udp_profile,
            &self.icmp_profile,
            &self.default_profile,
        ];
        for profile in profiles.into_iter().flatten() {
            if profile.rate_shift > MAX_RATE_SHIFT {
                return Err("rate_shift must be between 0 and 63");
            }
        }
        Ok(())
    }

    fn apply(self, cfg: &mut FirewallConfig) {
        if let Some(p) = self.tcp_profile {
            cfg.tcp_profile = p;
        }
        if let Some(p) = self.udp_profile {
            cfg.udp_profile = p;
        }
        if let Some(p) = self.icmp_profile {
            cfg.icmp_profile = p;
        }
        if let Some(p) = self.default_profile {
            cfg.default_profile = p;
        }
        if let Some(types) = self.protcol_allowed {
            cfg.protocol_allowed = types;
        }
        if let Some(activated) = self.ddos_activated {
            cfg.ddos_activated = activated;
        }
        if let Some(activated) = self.subnet_activated {
            cfg.subnet_activated = activated;
        }
        if let Some(adapter) = self.incoming_ethernet_adapter {
            cfg.incoming_ethernet_adapter = adapter;
        }
        if let Some(adapter) = self.output_ethernet_adapter {
            cfg.output_ethernet_adapter = adapter;
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/config",
    responses((status = 200, description = "Get current firewall configuration")),
    security(("cookie_auth" = []))
)]
/// get config from the firewall
pub async fn get_config(State(state): State<FirewallState>) -> impl IntoResponse {
    match state.config.read().await.get(&0, 0) {
        Ok(cfg) => Json(cfg).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "CONFIG map not initialized",
        )
            .into_response(),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/logs",
    responses((status = 200, description = "Recent firewall log entries", body = [LogEntry])),
    security(("cookie_auth" = []))
)]
pub async fn get_logs(
    State(state): State<FirewallState>,
    auth_session: AuthSession<Database>,
) -> impl IntoResponse {
    if !auth_session
        .user
        .as_ref()
        .is_some_and(|user| user.role == RolesUser::Admin)
    {
        return StatusCode::FORBIDDEN.into_response();
    }

    match state.logs.recent().await {
        Ok(entries) => Json(entries).into_response(),
        Err(error) => {
            tracing::error!("failed to read firewall logs: {error}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub async fn log_websocket(
    ws: WebSocketUpgrade,
    State(state): State<FirewallState>,
    auth_session: AuthSession<Database>,
) -> impl IntoResponse {
    if !auth_session
        .user
        .as_ref()
        .is_some_and(|user| user.role == RolesUser::Admin)
    {
        return StatusCode::FORBIDDEN.into_response();
    }

    let receiver = state.logs.tx.subscribe();
    ws.on_upgrade(move |socket| stream_logs(socket, receiver))
        .into_response()
}

async fn stream_logs(mut socket: WebSocket, mut receiver: broadcast::Receiver<LogEntry>) {
    while let Ok(entry) = receiver.recv().await {
        let Ok(message) = serde_json::to_string(&entry) else {
            continue;
        };
        if socket.send(Message::Text(message.into())).await.is_err() {
            break;
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/config/subnet/v4",
    responses((status = 200, description = "List IPv4 subnet rules", body = [SubnetMatchV4Update])),
    security(("cookie_auth" = []))
)]
pub async fn list_subnet_matching_v4(
    State(state): State<FirewallState>,
    auth_session: AuthSession<Database>,
) -> impl IntoResponse {
    if auth_session.user.is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match state.db.list_subnet_v4().await {
        Ok(entries) => Json(
            entries
                .into_iter()
                .map(|(network, prefix_len, action)| SubnetMatchV4Update {
                    network,
                    prefix_len,
                    action,
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(error) => {
            tracing::error!("failed to list IPv4 subnet rules: {error}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/config",
    request_body = ConfigPatch,
    responses(
        (status = 200, description = "Config updated successfully"),
        (status = 400, description = "Bad Request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal Server Error")
    ),
    security(("cookie_auth" = []))
)]
/// update firewall config
pub async fn update_config(
    State(state): State<FirewallState>,
    auth_session: AuthSession<Database>,
    Json(patch): Json<ConfigPatch>,
) -> impl IntoResponse {
    let user = match auth_session.user {
        Some(u) => u,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let caller = CallerContext {
        role: user.role.clone(),
        permissions: user.permissions,
    };
    if caller.role == RolesUser::Admin && caller.permissions.contains(ActionPermissions::MODIFY) {
        if let Err(msg) = patch.validate() {
            return (StatusCode::BAD_REQUEST, msg).into_response();
        }

        let mut config = state.config.write().await;
        let mut cfg = match config.get(&0, 0) {
            Ok(cfg) => cfg,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "CONFIG map not initialized",
                )
                    .into_response();
            }
        };

        patch.apply(&mut cfg);

        if let Some(ebpf) = &state.ebpf {
            let mut ebpf = ebpf.lock().await;
            if let Err(error) = ebpf.reboot(&cfg, &state.opt) {
                tracing::error!("failed to attach eBPF adapters: {error}");
                cfg.incoming_ethernet_adapter = None;
                cfg.output_ethernet_adapter = None;
                if let Err(clear_error) = config.set(0, cfg, 0) {
                    tracing::error!(
                        "failed to clear adapters after eBPF attach failure: {clear_error}"
                    );
                }
                if let Err(clear_error) = state.db.save_firewall_config(&cfg).await {
                    tracing::error!(
                        "failed to persist cleared adapters after eBPF attach failure: {clear_error}"
                    );
                }
                state
                    .logs
                    .record(
                        "ERROR",
                        &format!("Failed to attach eBPF adapters: {error}"),
                        Some(&user.username),
                    )
                    .await;
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to attach eBPF program to the selected adapters",
                )
                    .into_response();
            }
            let (incoming, output) = ebpf.attached_adapters();
            let attached = [incoming, output]
                .into_iter()
                .flatten()
                .map(|index| index.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            state
                .logs
                .record(
                    "INFO",
                    &format!(
                        "eBPF interface attachment succeeded{}",
                        if attached.is_empty() {
                            String::new()
                        } else {
                            format!(": {attached}")
                        }
                    ),
                    Some(&user.username),
                )
                .await;
        }

        if config.set(0, cfg, 0).is_err() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to update CONFIG map",
            )
                .into_response();
        }
        if let Err(error) = state.db.save_firewall_config(&cfg).await {
            tracing::error!("failed to persist firewall configuration: {error}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to persist firewall configuration",
            )
                .into_response();
        }

        state
            .logs
            .record(
                "INFO",
                "Firewall configuration updated",
                Some(&user.username),
            )
            .await;
        Json(cfg).into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}
#[utoipa::path(
    get,
    path = "/api/v1/config/allow_list/v4",
    responses((status = 200, description = "Get all items in the IPv4 Allow List")),
    security(("cookie_auth" = []))
)]
/// GET: Fetch all items in the IPv4 Allow List
pub async fn get_allow_list_v4(State(state): State<FirewallState>) -> impl IntoResponse {
    let map = state.allow_list_v4.read().await;

    let mut entries = Vec::with_capacity(4096);
    for (key, value) in map.iter().flatten() {
        entries.push((key, value));
    }

    Json(entries).into_response()
}
#[utoipa::path(
    post,
    path = "/api/v1/config/allow_list/v4",
    request_body = AllowListV4Update,
    responses((status = 200, description = "Item inserted or updated"), (status = 401, description = "Unauthorized")),
    security(("cookie_auth" = []))
)]
/// POST/PUT: Insert or update an item
pub async fn modify_allow_list_v4(
    State(state): State<FirewallState>,
    auth_session: AuthSession<Database>,
    Json(payload): Json<AllowListV4Update>,
) -> impl IntoResponse {
    let user = match auth_session.user {
        Some(u) => u,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let caller = CallerContext {
        role: user.role.clone(),
        permissions: user.permissions,
    };
    if caller.role == RolesUser::Admin && caller.permissions.contains(ActionPermissions::MODIFY) {
        let mut map = state.allow_list_v4.write().await;

        if map.insert(payload.key, payload.state, 0).is_err() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to insert into ALLOW_LIST_V4 map",
            )
                .into_response();
        }

        StatusCode::OK.into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}
#[utoipa::path(
    delete,
    path = "/api/v1/config/allow_list/v4",
    responses((status = 200, description = "All entries cleared"), (status = 401, description = "Unauthorized")),
    security(("cookie_auth" = []))
)]
/// DELETE: Clear all entries in the list
pub async fn clear_allow_list_v4(
    State(state): State<FirewallState>,
    auth_session: AuthSession<Database>,
) -> impl IntoResponse {
    let user = match auth_session.user {
        Some(u) => u,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let caller = CallerContext {
        role: user.role,
        permissions: user.permissions,
    };
    if caller.role == RolesUser::Admin && caller.permissions.contains(ActionPermissions::DELETE) {
        let mut map = state.allow_list_v4.write().await;

        let mut keys_to_remove = Vec::with_capacity(4096);
        for (key, _) in map.iter().flatten() {
            keys_to_remove.push(key);
        }

        for key in keys_to_remove {
            let _ = map.remove(&key);
        }

        StatusCode::OK.into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/config/allow_list/v6",
    responses((status = 200, description = "Get all items in the IPv6 Allow List")),
    security(("cookie_auth" = []))
)]
/// GET: Fetch all items in the IPv4 Allow List
pub async fn get_allow_list_v6(State(state): State<FirewallState>) -> impl IntoResponse {
    let map = state.allow_list_v6.read().await;

    let mut entries = Vec::with_capacity(4096);
    for (key, value) in map.iter().flatten() {
        entries.push((key, value));
    }

    Json(entries).into_response()
}

#[utoipa::path(
    post,
    path = "/api/v1/config/allow_list/v6",
    request_body = AllowListV6Update,
    responses((status = 200, description = "Item inserted or updated"), (status = 401, description = "Unauthorized")),
    security(("cookie_auth" = []))
)]
/// POST/PUT: Insert or update an item
pub async fn modify_allow_list_v6(
    State(state): State<FirewallState>,
    auth_session: AuthSession<Database>,
    Json(payload): Json<AllowListV6Update>,
) -> impl IntoResponse {
    let user = match auth_session.user {
        Some(u) => u,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let caller = CallerContext {
        role: user.role,
        permissions: user.permissions,
    };
    if caller.role == RolesUser::Admin && caller.permissions.contains(ActionPermissions::MODIFY) {
        let mut map = state.allow_list_v6.write().await;

        if map.insert(payload.key, payload.state, 0).is_err() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to insert into ALLOW_LIST_V6 map",
            )
                .into_response();
        }

        StatusCode::OK.into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

#[utoipa::path(
    delete,
    path = "/api/v1/config/allow_list/v6",
    responses((status = 200, description = "All entries cleared"), (status = 401, description = "Unauthorized")),
    security(("cookie_auth" = []))
)]
/// DELETE: Clear all entries in the list
pub async fn clear_allow_list_v6(
    State(state): State<FirewallState>,
    auth_session: AuthSession<Database>,
) -> impl IntoResponse {
    let user = match auth_session.user {
        Some(u) => u,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let caller = CallerContext {
        role: user.role,
        permissions: user.permissions,
    };
    if caller.role == RolesUser::Admin && caller.permissions.contains(ActionPermissions::DELETE) {
        let mut map = state.allow_list_v6.write().await;

        let mut keys_to_remove = Vec::with_capacity(4096);
        for (key, _) in map.iter().flatten() {
            keys_to_remove.push(key);
        }

        for key in keys_to_remove {
            let _ = map.remove(&key);
        }

        StatusCode::OK.into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/config/packet_counts/v4",
    responses((status = 200, description = "Get IPv4 packet counts")),
    security(("cookie_auth" = []))
)]
pub async fn get_packet_counts_v4(State(state): State<FirewallState>) -> impl IntoResponse {
    let map = state.packet_counts_v4.read().await;

    let mut entries = Vec::with_capacity(4096);
    for (key, value) in map.iter().flatten() {
        entries.push((key, value));
    }
    Json(entries).into_response()
}

#[utoipa::path(
    post,
    path = "/api/v1/config/packet_counts/v4",
    request_body = PacketCountV4Update,
    responses((status = 200, description = "Updated IPv4 packet count"), (status = 401, description = "Unauthorized")),
    security(("cookie_auth" = []))
)]
pub async fn modify_packet_counts_v4(
    State(state): State<FirewallState>,
    auth_session: AuthSession<Database>,
    Json(payload): Json<PacketCountV4Update>,
) -> impl IntoResponse {
    let user = match auth_session.user {
        Some(u) => u,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let caller = CallerContext {
        role: user.role,
        permissions: user.permissions,
    };
    if caller.role == RolesUser::Admin && caller.permissions.contains(ActionPermissions::MODIFY) {
        let mut map = state.packet_counts_v4.write().await;

        if map.insert(payload.key, payload.state, 0).is_err() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to insert into PACKET_COUNTS_V4 map",
            )
                .into_response();
        }
        StatusCode::OK.into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

#[utoipa::path(
    delete,
    path = "/api/v1/config/packet_counts/v4",
    responses((status = 200, description = "Cleared IPv4 packet counts"), (status = 401, description = "Unauthorized")),
    security(("cookie_auth" = []))
)]
pub async fn clear_packet_counts_v4(
    State(state): State<FirewallState>,
    auth_session: AuthSession<Database>,
) -> impl IntoResponse {
    let user = match auth_session.user {
        Some(u) => u,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let caller = CallerContext {
        role: user.role,
        permissions: user.permissions,
    };
    if caller.role == RolesUser::Admin && caller.permissions.contains(ActionPermissions::DELETE) {
        let mut map = state.packet_counts_v4.write().await;

        let mut keys_to_remove = Vec::with_capacity(4096);
        for (key, _) in map.iter().flatten() {
            keys_to_remove.push(key);
        }
        for key in keys_to_remove {
            let _ = map.remove(&key);
        }
        StatusCode::OK.into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}
#[utoipa::path(
    get,
    path = "/api/v1/config/packet_counts/v6",
    responses((status = 200, description = "Get IPv6 packet counts")),
    security(("cookie_auth" = []))
)]
pub async fn get_packet_counts_v6(State(state): State<FirewallState>) -> impl IntoResponse {
    let map = state.packet_counts_v6.read().await;

    let mut entries = Vec::with_capacity(4096);
    for (key, value) in map.iter().flatten() {
        entries.push((key, value));
    }
    Json(entries).into_response()
}

#[utoipa::path(
    post,
    path = "/api/v1/config/packet_counts/v6",
    request_body = PacketCountV6Update,
    responses((status = 200, description = "Updated IPv6 packet count"), (status = 401, description = "Unauthorized")),
    security(("cookie_auth" = []))
)]
pub async fn modify_packet_counts_v6(
    State(state): State<FirewallState>,
    auth_session: AuthSession<Database>,
    Json(payload): Json<PacketCountV6Update>,
) -> impl IntoResponse {
    let user = match auth_session.user {
        Some(u) => u,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let caller = CallerContext {
        role: user.role,
        permissions: user.permissions,
    };
    if caller.role == RolesUser::Admin && caller.permissions.contains(ActionPermissions::MODIFY) {
        let mut map = state.packet_counts_v6.write().await;

        if map.insert(payload.key, payload.state, 0).is_err() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to insert into PACKET_COUNTS_V6 map",
            )
                .into_response();
        }
        StatusCode::OK.into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

#[utoipa::path(
    delete,
    path = "/api/v1/config/packet_counts/v6",
    responses((status = 200, description = "Cleared IPv6 packet counts"), (status = 401, description = "Unauthorized")),
    security(("cookie_auth" = []))
)]
pub async fn clear_packet_counts_v6(
    State(state): State<FirewallState>,

    auth_session: AuthSession<Database>,
) -> impl IntoResponse {
    let user = match auth_session.user {
        Some(u) => u,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let caller = CallerContext {
        role: user.role,
        permissions: user.permissions,
    };
    if caller.role == RolesUser::Admin && caller.permissions.contains(ActionPermissions::DELETE) {
        let mut map = state.packet_counts_v6.write().await;

        let mut keys_to_remove = Vec::with_capacity(4096);
        for (key, _) in map.iter().flatten() {
            keys_to_remove.push(key);
        }
        for key in keys_to_remove {
            let _ = map.remove(&key);
        }
        StatusCode::OK.into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}
#[utoipa::path(
    post,
    path = "/api/v1/config/subnet/v4",
    request_body = SubnetMatchV4Update,
    responses((status = 200, description = "Added/Updated IPv4 subnet rule"), (status = 400, description = "Invalid prefix"), (status = 401, description = "Unauthorized")),
    security(("cookie_auth" = []))
)]
pub async fn modify_subnet_matching_v4(
    State(state): State<FirewallState>,
    auth_session: AuthSession<Database>,
    Json(payload): Json<SubnetMatchV4Update>,
) -> impl IntoResponse {
    let user = match auth_session.user {
        Some(u) => u,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let caller = CallerContext {
        role: user.role,
        permissions: user.permissions,
    };
    if caller.role == RolesUser::Admin && caller.permissions.contains(ActionPermissions::MODIFY) {
        if payload.prefix_len > 32 {
            return (
                StatusCode::BAD_REQUEST,
                "prefix_len must be between 0 and 32 for an IPv4 subnet",
            )
                .into_response();
        }

        let mut map = state.subnet_matching_v4.write().await;

        let key = Key::new(payload.prefix_len, payload.network.to_be());
        if map.insert(&key, payload.action, 0).is_err() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to insert into SUBNET_MATCHING_V4",
            )
                .into_response();
        }
        if let Err(error) = state
            .db
            .save_subnet_v4(payload.network, payload.prefix_len, payload.action)
            .await
        {
            tracing::error!("failed to persist IPv4 subnet rule: {error}");
            let _ = map.remove(&key);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        StatusCode::OK.into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

#[utoipa::path(
    delete,
    path = "/api/v1/config/subnet/v4",
    request_body = SubnetMatchV4Update,
    responses((status = 200, description = "Removed IPv4 subnet rule"), (status = 400, description = "Invalid prefix"), (status = 401, description = "Unauthorized")),
    security(("cookie_auth" = []))
)]
pub async fn remove_subnet_matching_v4(
    State(state): State<FirewallState>,
    auth_session: AuthSession<Database>,
    Json(payload): Json<SubnetMatchV4Update>,
) -> impl IntoResponse {
    let user = match auth_session.user {
        Some(u) => u,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let caller = CallerContext {
        role: user.role,
        permissions: user.permissions,
    };
    if caller.role == RolesUser::Admin && caller.permissions.contains(ActionPermissions::DELETE) {
        if payload.prefix_len > 32 {
            return (
                StatusCode::BAD_REQUEST,
                "prefix_len must be between 0 and 32 for an IPv4 subnet",
            )
                .into_response();
        }

        let mut map = state.subnet_matching_v4.write().await;

        let key = Key::new(payload.prefix_len, payload.network.to_be());
        if map.remove(&key).is_err() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to remove from SUBNET_MATCHING_V4",
            )
                .into_response();
        }
        if let Err(error) = state
            .db
            .delete_subnet_v4(payload.network, payload.prefix_len)
            .await
        {
            tracing::error!("failed to delete IPv4 subnet rule: {error}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        StatusCode::OK.into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/config/subnet/v6",
    responses((status = 200, description = "List IPv6 subnet rules", body = [SubnetMatchV6Update])),
    security(("cookie_auth" = []))
)]
pub async fn list_subnet_matching_v6(
    State(state): State<FirewallState>,
    auth_session: AuthSession<Database>,
) -> impl IntoResponse {
    if auth_session.user.is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match state.db.list_subnet_v6().await {
        Ok(entries) => Json(
            entries
                .into_iter()
                .map(|(network, prefix_len, action)| SubnetMatchV6Update {
                    network,
                    prefix_len,
                    action,
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(error) => {
            tracing::error!("failed to list IPv6 subnet rules: {error}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/config/subnet/v6",
    request_body = SubnetMatchV6Update,
    responses((status = 200, description = "Added/Updated IPv6 subnet rule"), (status = 400, description = "Invalid prefix"), (status = 401, description = "Unauthorized")),
    security(("cookie_auth" = []))
)]
pub async fn modify_subnet_matching_v6(
    State(state): State<FirewallState>,
    auth_session: AuthSession<Database>,
    Json(payload): Json<SubnetMatchV6Update>,
) -> impl IntoResponse {
    let user = match auth_session.user {
        Some(u) => u,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let caller = CallerContext {
        role: user.role,
        permissions: user.permissions,
    };
    if caller.role == RolesUser::Admin && caller.permissions.contains(ActionPermissions::MODIFY) {
        if payload.prefix_len > 128 {
            return (
                StatusCode::BAD_REQUEST,
                "prefix_len must be between 0 and 128 for an IPv6 subnet",
            )
                .into_response();
        }

        let mut map = state.subnet_matching_v6.write().await;

        let key = Key::new(payload.prefix_len, payload.network);
        if map.insert(&key, payload.action, 0).is_err() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to insert into SUBNET_MATCHING_V6",
            )
                .into_response();
        }
        if let Err(error) = state
            .db
            .save_subnet_v6(payload.network, payload.prefix_len, payload.action)
            .await
        {
            tracing::error!("failed to persist IPv6 subnet rule: {error}");
            let _ = map.remove(&key);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        StatusCode::OK.into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

#[utoipa::path(
    delete,
    path = "/api/v1/config/subnet/v6",
    request_body = SubnetMatchV6Update,
    responses((status = 200, description = "Removed IPv6 subnet rule"), (status = 400, description = "Invalid prefix"), (status = 401, description = "Unauthorized")),
    security(("cookie_auth" = []))
)]
pub async fn remove_subnet_matching_v6(
    State(state): State<FirewallState>,
    auth_session: AuthSession<Database>,
    Json(payload): Json<SubnetMatchV6Update>,
) -> impl IntoResponse {
    let user = match auth_session.user {
        Some(u) => u,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let caller = CallerContext {
        role: user.role,
        permissions: user.permissions,
    };
    if caller.role == RolesUser::Admin && caller.permissions.contains(ActionPermissions::DELETE) {
        if payload.prefix_len > 128 {
            return (
                StatusCode::BAD_REQUEST,
                "prefix_len must be between 0 and 128 for an IPv6 subnet",
            )
                .into_response();
        }

        let mut map = state.subnet_matching_v6.write().await;

        let key = Key::new(payload.prefix_len, payload.network);
        if map.remove(&key).is_err() {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to remove from SUBNET_MATCHING_V6",
            )
                .into_response();
        }
        if let Err(error) = state
            .db
            .delete_subnet_v6(payload.network, payload.prefix_len)
            .await
        {
            tracing::error!("failed to delete IPv6 subnet rule: {error}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        StatusCode::OK.into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}
/// Router for config
pub fn config_router() -> Router<FirewallState> {
    Router::new()
        .route("/", get(get_config).post(update_config))
        .route("/adapters", get(get_ebpf_adapters))
        .route("/ebpf/shutdown", post(shutdown_ebpf))
        .route("/ebpf/restart", post(restart_ebpf))
        .route("/traffic", get(get_traffic_stats))
        .route(
            "/allow_list/v4",
            get(get_allow_list_v4)
                .post(modify_allow_list_v4)
                .delete(clear_allow_list_v4),
        )
        .route(
            "/allow_list/v6",
            get(get_allow_list_v6)
                .post(modify_allow_list_v6)
                .delete(clear_allow_list_v6),
        )
        // Packet Counts
        .route(
            "/packet_counts/v4",
            get(get_packet_counts_v4)
                .post(modify_packet_counts_v4)
                .delete(clear_packet_counts_v4),
        )
        .route(
            "/packet_counts/v6",
            get(get_packet_counts_v6)
                .post(modify_packet_counts_v6)
                .delete(clear_packet_counts_v6),
        )
        // Subnets (Notice: No GET or bulk DELETE)
        .route(
            "/subnet/v4",
            get(list_subnet_matching_v4)
                .post(modify_subnet_matching_v4)
                .delete(remove_subnet_matching_v4),
        )
        .route(
            "/subnet/v6",
            get(list_subnet_matching_v6)
                .post(modify_subnet_matching_v6)
                .delete(remove_subnet_matching_v6),
        )
}

async fn authorized_ebpf_action(
    state: &FirewallState,
    auth_session: &AuthSession<Database>,
) -> Result<crate::auth::AppUser, StatusCode> {
    let user = auth_session.user.clone().ok_or(StatusCode::UNAUTHORIZED)?;
    let caller = CallerContext {
        role: user.role.clone(),
        permissions: user.permissions,
    };
    if caller.role != RolesUser::Admin || !caller.permissions.contains(ActionPermissions::MODIFY) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if state.ebpf.is_none() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    Ok(user)
}

pub async fn shutdown_ebpf(
    State(state): State<FirewallState>,
    auth_session: AuthSession<Database>,
) -> impl IntoResponse {
    let user = match authorized_ebpf_action(&state, &auth_session).await {
        Ok(user) => user,
        Err(status) => return status.into_response(),
    };
    let ebpf = state.ebpf.as_ref().expect("checked above");
    let mut ebpf = ebpf.lock().await;
    if let Err(error) = ebpf.shut_down_working_ebpf() {
        state
            .logs
            .record(
                "ERROR",
                &format!("eBPF shutdown failed: {error}"),
                Some(&user.username),
            )
            .await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to shut down eBPF",
        )
            .into_response();
    }
    state
        .logs
        .record("INFO", "eBPF program shut down", Some(&user.username))
        .await;
    StatusCode::NO_CONTENT.into_response()
}

pub async fn restart_ebpf(
    State(state): State<FirewallState>,
    auth_session: AuthSession<Database>,
) -> impl IntoResponse {
    let user = match authorized_ebpf_action(&state, &auth_session).await {
        Ok(user) => user,
        Err(status) => return status.into_response(),
    };
    let config_map = state.config.write().await;
    let cfg = match config_map.get(&0, 0) {
        Ok(cfg) => cfg,
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "CONFIG map unavailable").into_response();
        }
    };
    let ebpf = state.ebpf.as_ref().expect("checked above");
    let mut ebpf = ebpf.lock().await;
    if cfg.incoming_ethernet_adapter.is_none() && cfg.output_ethernet_adapter.is_none() {
        return StatusCode::NO_CONTENT.into_response();
    }
    if let Err(error) = ebpf.reboot(&cfg, &state.opt) {
        state
            .logs
            .record(
                "ERROR",
                &format!("eBPF restart failed: {error}"),
                Some(&user.username),
            )
            .await;
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to restart eBPF").into_response();
    }
    state
        .logs
        .record("INFO", "eBPF program restarted", Some(&user.username))
        .await;
    StatusCode::NO_CONTENT.into_response()
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        extract::Request,
    };
    use axum_login::AuthManagerLayerBuilder;
    use hyper::Method;
    use tower::ServiceExt;
    use tower_sessions::{
        MemoryStore,
        SessionManagerLayer,
    };

    use super::*;
    const BPF_F_NO_PREALLOC: u32 = 1;

    // Helper to create a test firewall state
    async fn create_test_state() -> FirewallState {
        let mut config_map = Array::<MapData, FirewallConfig>::create(1, 0).unwrap();
        let default_config = FirewallConfig::default();
        config_map.set(0, default_config, 0).unwrap();

        let allow_list_v4 =
            HashMap::<MapData, Ipv4Packet, AllowListState>::create(4096, 0).unwrap();
        let allow_list_v6 =
            HashMap::<MapData, Ipv6Packet, AllowListState>::create(4096, 0).unwrap();
        let packet_counts_v4 =
            HashMap::<MapData, Ipv4Packet, TokenBucketState>::create(4096, 0).unwrap();
        let packet_counts_v6 =
            HashMap::<MapData, Ipv6Packet, TokenBucketState>::create(4096, 0).unwrap();
        let subnet_matching_v4 =
            LpmTrie::<MapData, u32, Action>::create(2048, BPF_F_NO_PREALLOC).unwrap();
        let subnet_matching_v6 =
            LpmTrie::<MapData, [u32; 4], Action>::create(2048, BPF_F_NO_PREALLOC).unwrap();
        // Actually initialize an in-memory database instead of pretending it implements Default
        let db = crate::db::Database::new("sqlite::memory:")
            .await
            .expect("Failed to create test DB");

        FirewallState {
            logs: Arc::new(LogStore::new(db.clone())),
            ebpf: None,
            opt: Opt {
                http_port: 0,
                incoming_adapter: None,
                output_adapter: None,
            },
            db,
            config: Arc::new(RwLock::new(config_map)),
            allow_list_v4: Arc::new(RwLock::new(allow_list_v4)),
            allow_list_v6: Arc::new(RwLock::new(allow_list_v6)),
            packet_counts_v4: Arc::new(RwLock::new(packet_counts_v4)),
            packet_counts_v6: Arc::new(RwLock::new(packet_counts_v6)),
            subnet_matching_v4: Arc::new(RwLock::new(subnet_matching_v4)),
            subnet_matching_v6: Arc::new(RwLock::new(subnet_matching_v6)),
        }
    }

    use crate::{
        auth::AppUser,
        db::{
            ActionPermissions,
            RolesUser,
        },
    };

    async fn make_request(
        state: FirewallState,
        method: Method,
        path: &str,
        body_opt: Option<String>,
        mock_user: Option<AppUser>,
    ) -> (StatusCode, String) {
        let has_body = body_opt.is_some();

        let mut app_user = mock_user.unwrap_or_else(|| AppUser {
            id: 0,
            username: format!(
                "test_admin_{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ),
            role: RolesUser::Admin,
            permissions: ActionPermissions::MODIFY | ActionPermissions::DELETE,
            password_hash: "dummy_hash".to_string(),
            password_must_be_changed: false,
        });

        let role_str = match app_user.role {
            RolesUser::Admin => "admin",
            RolesUser::Viewer => "viewer",
        };

        let _ = sqlx::query!(
        r#"INSERT INTO users (username, password_hash, role, action_permissions, password_must_be_changed, is_active)
           VALUES (?, ?, ?, ?, 0, 1)
           ON CONFLICT(username) DO UPDATE SET
           role = excluded.role,
           action_permissions = excluded.action_permissions"#,
        app_user.username,
        app_user.password_hash,
        role_str,
        app_user.permissions.bits()
    )
    .execute(&state.db.pool)
    .await
    .unwrap();

        let real_id =
            sqlx::query_scalar!("SELECT id FROM users WHERE username = ?", app_user.username)
                .fetch_one(&state.db.pool)
                .await
                .unwrap();

        app_user.id = real_id;

        let store = MemoryStore::default();
        let session_layer = SessionManagerLayer::new(store);
        let auth_layer = AuthManagerLayerBuilder::new(state.db.clone(), session_layer).build();

        let app = config_router()
            .route(
                "/__mock_login",
                axum::routing::get({
                    let app_user = app_user.clone();
                    move |mut auth: axum_login::AuthSession<Database>| async move {
                        auth.login(&app_user).await.unwrap();
                        StatusCode::OK
                    }
                }),
            )
            .with_state(state.clone())
            .layer(auth_layer);

        let login_req = Request::builder()
            .uri("/__mock_login")
            .body(Body::empty())
            .unwrap();
        let login_res = app.clone().oneshot(login_req).await.unwrap();
        let cookie = login_res
            .headers()
            .get(hyper::header::SET_COOKIE)
            .expect("Failed to get SET_COOKIE header from mock login")
            .to_str()
            .unwrap()
            .to_string();

        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header(hyper::header::COOKIE, cookie)
            .body(Body::from(body_opt.unwrap_or_default()))
            .unwrap();

        if has_body {
            req.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/json"),
            );
        }

        let response = app.oneshot(req).await.unwrap();
        let status = response.status();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        (status, String::from_utf8_lossy(&body_bytes).to_string())
    }

    #[tokio::test]
    async fn test_config_endpoint() {
        let state = create_test_state().await;

        let (status, body) = make_request(state.clone(), Method::GET, "/", None, None).await;
        assert_eq!(status, StatusCode::OK);

        let config: FirewallConfig = serde_json::from_str(&body).unwrap();
        assert!(config.ddos_activated);
        assert_eq!(
            config.protocol_allowed,
            ActivaterEtherTypes::IPV4 | ActivaterEtherTypes::IPV6
        );

        let patch = serde_json::json!({
            "tcp_profile": {
                "rate_shift": 21,
                "burst": 500
            },
            "ddos_activated": false
        });

        let (status, _) = make_request(
            state.clone(),
            Method::POST,
            "/",
            Some(patch.to_string()),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = make_request(state.clone(), Method::GET, "/", None, None).await;
        assert_eq!(status, StatusCode::OK);
        let config: FirewallConfig = serde_json::from_str(&body).unwrap();
        assert_eq!(config.tcp_profile.rate_shift, 21);
        assert_eq!(config.tcp_profile.burst, 500);
        assert!(!config.ddos_activated);
    }

    #[tokio::test]
    async fn test_allow_list_v4_lifecycle() {
        let state = create_test_state().await;

        let entry = serde_json::json!({
            "key": {
                "source_addr": 16843264,
                "destination_addr": 16843265,
                "source_port": 12345,
                "destination_port": 80,
                "protocol": 6
            },
            "state": {
                "action": "Allow",
                "last_seen": 1000000000
            }
        });

        let (status, _) = make_request(
            state.clone(),
            Method::POST,
            "/allow_list/v4",
            Some(entry.to_string()),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) =
            make_request(state.clone(), Method::GET, "/allow_list/v4", None, None).await;
        assert_eq!(status, StatusCode::OK);
        let entries: Vec<(Ipv4Packet, AllowListState)> = serde_json::from_str(&body).unwrap();
        assert_eq!(entries.len(), 1);
        let entry = entries.first().expect("allow-list entry should exist");
        assert_eq!(entry.0.source_addr, 16843264);
        assert_eq!(entry.1.action, Action::Allow);

        let (status, _) =
            make_request(state.clone(), Method::DELETE, "/allow_list/v4", None, None).await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) =
            make_request(state.clone(), Method::GET, "/allow_list/v4", None, None).await;
        assert_eq!(status, StatusCode::OK);
        let entries: Vec<(Ipv4Packet, AllowListState)> = serde_json::from_str(&body).unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn test_subnet_matching_v4() {
        let state = create_test_state().await;

        let rule = serde_json::json!({
            "network": 16843264,
            "prefix_len": 24,
            "action": "Allow"
        });

        let (status, _) = make_request(
            state.clone(),
            Method::POST,
            "/subnet/v4",
            Some(rule.to_string()),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let key = aya::maps::lpm_trie::Key::new(24, 16843264);
        {
            let subnet_map = state.subnet_matching_v4.read().await;
            let action = subnet_map.get(&key, 0).unwrap();
            assert_eq!(action, Action::Allow);
        }

        let (status, _) = make_request(
            state.clone(),
            Method::DELETE,
            "/subnet/v4",
            Some(rule.to_string()),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let subnet_map = state.subnet_matching_v4.read().await;
        assert!(subnet_map.get(&key, 0).is_err());
    }

    #[tokio::test]
    async fn test_rate_limiting_state() {
        let state = create_test_state().await;

        let entry = serde_json::json!({
            "key": {
                "source_addr": 16843264,
                "destination_addr": 16843265,
                "source_port": 12345,
                "destination_port": 80,
                "protocol": 6
            },
            "state": {
                "tokens": 100,
                "last_update": 1000000000
            }
        });

        let (status, _) = make_request(
            state.clone(),
            Method::POST,
            "/packet_counts/v4",
            Some(entry.to_string()),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) =
            make_request(state.clone(), Method::GET, "/packet_counts/v4", None, None).await;
        assert_eq!(status, StatusCode::OK);
        let entries: Vec<(Ipv4Packet, TokenBucketState)> = serde_json::from_str(&body).unwrap();
        assert_eq!(entries.len(), 1);
        let entry = entries.first().expect("packet-count entry should exist");
        assert_eq!(entry.1.tokens, 100);

        let (status, _) = make_request(
            state.clone(),
            Method::DELETE,
            "/packet_counts/v4",
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) =
            make_request(state.clone(), Method::GET, "/packet_counts/v4", None, None).await;
        assert_eq!(status, StatusCode::OK);
        let entries: Vec<(Ipv4Packet, TokenBucketState)> = serde_json::from_str(&body).unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn test_invalid_config_updates() {
        let state = create_test_state().await;

        let (status, _) = make_request(
            state.clone(),
            Method::POST,
            "/",
            Some("invalid json".to_string()),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let patch = serde_json::json!({
            "tcp_profile": {
                "rate_shift": 1000,
                "burst": 500
            }
        });

        let (status, _) = make_request(
            state.clone(),
            Method::POST,
            "/",
            Some(patch.to_string()),
            None,
        )
        .await;
        assert_ne!(status, StatusCode::OK); // Expect invalid rate_shift to be rejected

        let rule = serde_json::json!({
            "network": 16843264,
            "prefix_len": 33,
            "action": "Allow"
        });

        let (status, _) = make_request(
            state.clone(),
            Method::POST,
            "/subnet/v4",
            Some(rule.to_string()),
            None,
        )
        .await;
        assert_ne!(status, StatusCode::OK); // Expect invalid prefix_len (33) to be rejected

        let subnet_map = state.subnet_matching_v4.read().await;
        let key = aya::maps::lpm_trie::Key::new(33, 16843264);
        assert!(subnet_map.get(&key, 0).is_err());
    }

    #[tokio::test]
    async fn test_concurrent_config_updates() {
        let state = create_test_state().await;

        let mut handles = Vec::new();
        for i in 0..10 {
            let value = state.clone();
            let handle = tokio::spawn(async move {
                let patch = serde_json::json!({
                    "tcp_profile": {
                        "rate_shift": 20 + i as u64,
                        "burst": 1000 + i as u64
                    }
                });

                let (status, _) = make_request(
                    value.clone(),
                    Method::POST,
                    "/",
                    Some(patch.to_string()),
                    None,
                )
                .await;
                status
            });
            handles.push(handle);
        }

        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.await.unwrap());
        }

        for result in results {
            assert_eq!(result, StatusCode::OK);
        }

        let (status, body) = make_request(state.clone(), Method::GET, "/", None, None).await;
        assert_eq!(status, StatusCode::OK);
        let config: FirewallConfig = serde_json::from_str(&body).unwrap();

        let valid_update = (0..10).any(|i| {
            config.tcp_profile.rate_shift == 20 + i as u64
                && config.tcp_profile.burst == 1000 + i as u64
        });
        assert!(valid_update);
    }

    #[tokio::test]
    async fn test_ipv6_allow_list() {
        let state = create_test_state().await;

        let entry = serde_json::json!({
            "key": {
                "source_addr": [16843264, 0, 0, 1],
                "destination_addr": [16843265, 0, 0, 1],
                "source_port": 12345,
                "destination_port": 80,
                "protocol": 6
            },
            "state": {
                "action": "Allow",
                "last_seen": 1000000000
            }
        });

        let (status, _) = make_request(
            state.clone(),
            Method::POST,
            "/allow_list/v6",
            Some(entry.to_string()),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) =
            make_request(state.clone(), Method::GET, "/allow_list/v6", None, None).await;
        assert_eq!(status, StatusCode::OK);
        let entries: Vec<(Ipv6Packet, AllowListState)> = serde_json::from_str(&body).unwrap();
        assert_eq!(entries.len(), 1);
        let entry = entries.first().expect("allow-list entry should exist");
        assert_eq!(entry.0.source_addr, [16843264, 0, 0, 1]);
        assert_eq!(entry.1.action, Action::Allow);

        let (status, _) =
            make_request(state.clone(), Method::DELETE, "/allow_list/v6", None, None).await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) =
            make_request(state.clone(), Method::GET, "/allow_list/v6", None, None).await;
        assert_eq!(status, StatusCode::OK);
        let entries: Vec<(Ipv6Packet, AllowListState)> = serde_json::from_str(&body).unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn test_subnet_matching_v6() {
        let state = create_test_state().await;

        let rule = serde_json::json!({
            "network": [16843264, 0, 0, 0],
            "prefix_len": 96,
            "action": "Allow"
        });

        let (status, _) = make_request(
            state.clone(),
            Method::POST,
            "/subnet/v6",
            Some(rule.to_string()),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let key = aya::maps::lpm_trie::Key::new(96, [16843264, 0, 0, 0]);
        {
            let subnet_map = state.subnet_matching_v6.read().await;
            let action = subnet_map.get(&key, 0).unwrap();
            assert_eq!(action, Action::Allow);
        }

        let (status, _) = make_request(
            state.clone(),
            Method::DELETE,
            "/subnet/v6",
            Some(rule.to_string()),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let subnet_map = state.subnet_matching_v6.read().await;
        assert!(subnet_map.get(&key, 0).is_err());
    }

    #[tokio::test]
    async fn test_packet_counts_v6() {
        let state = create_test_state().await;

        let entry = serde_json::json!({
            "key": {
                "source_addr": [16843264, 0, 0, 1],
                "destination_addr": [16843265, 0, 0, 1],
                "source_port": 12345,
                "destination_port": 80,
                "protocol": 6
            },
            "state": {
                "tokens": 100,
                "last_update": 1000000000
            }
        });

        let (status, _) = make_request(
            state.clone(),
            Method::POST,
            "/packet_counts/v6",
            Some(entry.to_string()),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) =
            make_request(state.clone(), Method::GET, "/packet_counts/v6", None, None).await;
        assert_eq!(status, StatusCode::OK);
        let entries: Vec<(Ipv6Packet, TokenBucketState)> = serde_json::from_str(&body).unwrap();
        assert_eq!(entries.len(), 1);
        let entry = entries.first().expect("packet-count entry should exist");
        assert_eq!(entry.1.tokens, 100);

        let (status, _) = make_request(
            state.clone(),
            Method::DELETE,
            "/packet_counts/v6",
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) =
            make_request(state.clone(), Method::GET, "/packet_counts/v6", None, None).await;
        assert_eq!(status, StatusCode::OK);
        let entries: Vec<(Ipv6Packet, TokenBucketState)> = serde_json::from_str(&body).unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn test_boundary_conditions() {
        let state = create_test_state().await;

        let rule = serde_json::json!({
            "network": 4294967295_u32,
            "prefix_len": 32,
            "action": "Deny"
        });

        let (status, _) = make_request(
            state.clone(),
            Method::POST,
            "/subnet/v4",
            Some(rule.to_string()),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        {
            let subnet_map = state.subnet_matching_v4.read().await;
            let key = aya::maps::lpm_trie::Key::new(32, u32::MAX);
            let action = subnet_map.get(&key, 0).unwrap();
            assert_eq!(action, Action::Deny);
        }

        let rule = serde_json::json!({
            "network": [4294967295_u32, 4294967295_u32, 4294967295_u32, 4294967295_u32],
            "prefix_len": 128,
            "action": "Deny"
        });

        let (status, _) = make_request(
            state.clone(),
            Method::POST,
            "/subnet/v6",
            Some(rule.to_string()),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let subnet_map = state.subnet_matching_v6.read().await;
        let key = aya::maps::lpm_trie::Key::new(128, [4294967295u32; 4]);
        let action = subnet_map.get(&key, 0).unwrap();
        assert_eq!(action, Action::Deny);
    }

    #[tokio::test]
    async fn test_empty_operations() {
        let state = create_test_state().await;

        let (status, _) =
            make_request(state.clone(), Method::DELETE, "/allow_list/v4", None, None).await;
        assert_eq!(status, StatusCode::OK);

        let (status, _) = make_request(
            state.clone(),
            Method::DELETE,
            "/packet_counts/v4",
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, _) =
            make_request(state.clone(), Method::DELETE, "/allow_list/v6", None, None).await;
        assert_eq!(status, StatusCode::OK);

        let (status, _) = make_request(
            state.clone(),
            Method::DELETE,
            "/packet_counts/v6",
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_config_persistence() {
        let state = create_test_state().await;

        let patch = serde_json::json!({
            "tcp_profile": {
                "rate_shift": 21,
                "burst": 500
            },
            "ddos_activated": false
        });

        let (status, _) = make_request(
            state.clone(),
            Method::POST,
            "/",
            Some(patch.to_string()),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        for _ in 0..5 {
            let (status, body) = make_request(state.clone(), Method::GET, "/", None, None).await;
            assert_eq!(status, StatusCode::OK);
            let config: FirewallConfig = serde_json::from_str(&body).unwrap();
            assert_eq!(config.tcp_profile.rate_shift, 21);
            assert_eq!(config.tcp_profile.burst, 500);
            assert!(!config.ddos_activated);
        }
    }
}
