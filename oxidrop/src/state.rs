use std::sync::Arc;

use axum::{
    Json,
    Router,
    extract::State,
    response::IntoResponse,
    routing::{
        get,
        post,
    },
};
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
use tokio::sync::RwLock;

/// Firewall internal state
#[derive(Clone)]
pub struct FirewallState {
    pub config: Arc<RwLock<Array<MapData, FirewallConfig>>>,
    pub allow_list_v4: Arc<RwLock<HashMap<MapData, Ipv4Packet, AllowListState>>>,
    pub allow_list_v6: Arc<RwLock<HashMap<MapData, Ipv6Packet, AllowListState>>>,
    pub packet_counts_v4: Arc<RwLock<HashMap<MapData, Ipv4Packet, TokenBucketState>>>,
    pub packet_counts_v6: Arc<RwLock<HashMap<MapData, Ipv6Packet, TokenBucketState>>>,
    pub subnet_matching_v4: Arc<RwLock<LpmTrie<MapData, u32, Action>>>,
    pub subnet_matching_v6: Arc<RwLock<LpmTrie<MapData, [u32; 4], Action>>>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct AllowListV4Update {
    pub key: Ipv4Packet,
    pub state: AllowListState,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct AllowListV6Update {
    pub key: Ipv6Packet,
    pub state: AllowListState,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct PacketCountV4Update {
    pub key: Ipv4Packet,
    pub state: TokenBucketState,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PacketCountV6Update {
    pub key: Ipv6Packet,
    pub state: TokenBucketState,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct SubnetMatchV4Update {
    pub network: u32,
    pub prefix_len: u32,
    pub action: Action,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubnetMatchV6Update {
    pub network: [u32; 4],
    pub prefix_len: u32,
    pub action: Action,
}

// But we need a "patch-style" request type that allows partial updates
#[derive(Debug, Serialize, Deserialize)]
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
    pub protcol_allowed: Option<ActivaterEtherTypes>,
    #[serde(default)]
    pub ddos_activated: Option<bool>,
    #[serde(default)]
    pub incoming_ethernet_adapter: Option<usize>,
    #[serde(default)]
    pub output_ethernet_adapter: Option<usize>,
}

/// get config from the firewall
pub async fn get_config(State(state): State<Arc<RwLock<FirewallState>>>) -> impl IntoResponse {
    let state_guard = state.read().await;
    match state_guard.config.read().await.get(&0, 0) {
        Ok(cfg) => Json(cfg).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "CONFIG map not initialized",
        )
            .into_response(),
    }
}

/// update firewall config
pub async fn update_config(
    State(state): State<Arc<RwLock<FirewallState>>>,
    Json(patch): Json<ConfigPatch>,
) -> impl IntoResponse {
    let state_guard = state.write_owned().await;
    let mut cfg = match state_guard.config.read().await.get(&0, 0) {
        Ok(cfg) => cfg,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "CONFIG map not initialized",
            )
                .into_response();
        }
    };

    if let Some(p) = patch.tcp_profile {
        cfg.tcp_profile = p;
    }
    if let Some(p) = patch.udp_profile {
        cfg.udp_profile = p;
    }
    if let Some(p) = patch.icmp_profile {
        cfg.icmp_profile = p;
    }
    if let Some(p) = patch.default_profile {
        cfg.default_profile = p;
    }
    if let Some(types) = patch.protcol_allowed {
        cfg.protcol_allowed = types;
    }
    if let Some(activated) = patch.ddos_activated {
        cfg.ddos_activated = activated;
    }
    if let Some(adapter) = patch.incoming_ethernet_adapter {
        cfg.incoming_ethernet_adapter = Some(adapter);
    }
    if let Some(adapter) = patch.output_ethernet_adapter {
        cfg.output_ethernet_adapter = Some(adapter);
    }

    if state_guard.config.write().await.set(0, &cfg, 0).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to update CONFIG map",
        )
            .into_response();
    }

    Json(cfg).into_response()
}
/// GET: Fetch all items in the IPv4 Allow List
pub async fn get_allow_list_v4(
    State(state): State<Arc<RwLock<FirewallState>>>,
) -> impl IntoResponse {
    let state_guard = state.read().await;
    let map = state_guard.allow_list_v4.read().await;

    let mut entries = Vec::with_capacity(4096);
    for item in map.iter() {
        if let Ok((key, value)) = item {
            entries.push((key, value));
        }
    }

    Json(entries).into_response()
}

/// POST/PUT: Insert or update an item
pub async fn modify_allow_list_v4(
    State(state): State<Arc<RwLock<FirewallState>>>,
    Json(payload): Json<AllowListV4Update>,
) -> impl IntoResponse {
    let state_guard = state.read().await;
    let mut map = state_guard.allow_list_v4.write().await;

    if map.insert(&payload.key, &payload.state, 0).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to insert into ALLOW_LIST_V4 map",
        )
            .into_response();
    }

    StatusCode::OK.into_response()
}

/// DELETE: Clear all entries in the list
pub async fn clear_allow_list_v4(
    State(state): State<Arc<RwLock<FirewallState>>>,
) -> impl IntoResponse {
    let state_guard = state.read().await;
    let mut map = state_guard.allow_list_v4.write().await;

    let mut keys_to_remove = Vec::with_capacity(4096);
    for item in map.iter() {
        if let Ok((key, _)) = item {
            keys_to_remove.push(key);
        }
    }

    for key in keys_to_remove {
        let _ = map.remove(&key);
    }

    StatusCode::OK.into_response()
}

/// GET: Fetch all items in the IPv4 Allow List
pub async fn get_allow_list_v6(
    State(state): State<Arc<RwLock<FirewallState>>>,
) -> impl IntoResponse {
    let state_guard = state.read().await;
    let map = state_guard.allow_list_v6.read().await;

    let mut entries = Vec::with_capacity(4096);
    for item in map.iter() {
        if let Ok((key, value)) = item {
            entries.push((key, value));
        }
    }

    Json(entries).into_response()
}

/// POST/PUT: Insert or update an item
pub async fn modify_allow_list_v6(
    State(state): State<Arc<RwLock<FirewallState>>>,
    Json(payload): Json<AllowListV6Update>,
) -> impl IntoResponse {
    let state_guard = state.read().await;
    let mut map = state_guard.allow_list_v6.write().await;

    if map.insert(&payload.key, &payload.state, 0).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to insert into ALLOW_LIST_V6 map",
        )
            .into_response();
    }

    StatusCode::OK.into_response()
}

/// DELETE: Clear all entries in the list
pub async fn clear_allow_list_v6(
    State(state): State<Arc<RwLock<FirewallState>>>,
) -> impl IntoResponse {
    let state_guard = state.read().await;
    let mut map = state_guard.allow_list_v6.write().await;

    let mut keys_to_remove = Vec::with_capacity(4096);
    for item in map.iter() {
        if let Ok((key, _)) = item {
            keys_to_remove.push(key);
        }
    }

    for key in keys_to_remove {
        let _ = map.remove(&key);
    }

    StatusCode::OK.into_response()
}

pub async fn get_packet_counts_v4(
    State(state): State<Arc<RwLock<FirewallState>>>,
) -> impl IntoResponse {
    let state_guard = state.read().await;
    let map = state_guard.packet_counts_v4.read().await;

    let mut entries = Vec::with_capacity(4096);
    for item in map.iter() {
        if let Ok((key, value)) = item {
            entries.push((key, value));
        }
    }
    Json(entries).into_response()
}

pub async fn modify_packet_counts_v4(
    State(state): State<Arc<RwLock<FirewallState>>>,
    Json(payload): Json<PacketCountV4Update>,
) -> impl IntoResponse {
    let state_guard = state.read().await;
    let mut map = state_guard.packet_counts_v4.write().await;

    if map.insert(&payload.key, &payload.state, 0).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to insert into PACKET_COUNTS_V4 map",
        )
            .into_response();
    }
    StatusCode::OK.into_response()
}

pub async fn clear_packet_counts_v4(
    State(state): State<Arc<RwLock<FirewallState>>>,
) -> impl IntoResponse {
    let state_guard = state.read().await;
    let mut map = state_guard.packet_counts_v4.write().await;

    let mut keys_to_remove = Vec::with_capacity(4096);
    for item in map.iter() {
        if let Ok((key, _)) = item {
            keys_to_remove.push(key);
        }
    }
    for key in keys_to_remove {
        let _ = map.remove(&key);
    }
    StatusCode::OK.into_response()
}
pub async fn get_packet_counts_v6(
    State(state): State<Arc<RwLock<FirewallState>>>,
) -> impl IntoResponse {
    let state_guard = state.read().await;
    let map = state_guard.packet_counts_v6.read().await;

    let mut entries = Vec::with_capacity(4096);
    for item in map.iter() {
        if let Ok((key, value)) = item {
            entries.push((key, value));
        }
    }
    Json(entries).into_response()
}

pub async fn modify_packet_counts_v6(
    State(state): State<Arc<RwLock<FirewallState>>>,
    Json(payload): Json<PacketCountV6Update>,
) -> impl IntoResponse {
    let state_guard = state.read().await;
    let mut map = state_guard.packet_counts_v6.write().await;

    if map.insert(&payload.key, &payload.state, 0).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to insert into PACKET_COUNTS_V6 map",
        )
            .into_response();
    }
    StatusCode::OK.into_response()
}

pub async fn clear_packet_counts_v6(
    State(state): State<Arc<RwLock<FirewallState>>>,
) -> impl IntoResponse {
    let state_guard = state.read().await;
    let mut map = state_guard.packet_counts_v6.write().await;

    let mut keys_to_remove = Vec::with_capacity(4096);
    for item in map.iter() {
        if let Ok((key, _)) = item {
            keys_to_remove.push(key);
        }
    }
    for key in keys_to_remove {
        let _ = map.remove(&key);
    }
    StatusCode::OK.into_response()
}
pub async fn modify_subnet_matching_v4(
    State(state): State<Arc<RwLock<FirewallState>>>,
    Json(payload): Json<SubnetMatchV4Update>,
) -> impl IntoResponse {
    let state_guard = state.read().await;
    let mut map = state_guard.subnet_matching_v4.write().await;

    let key = Key::new(payload.prefix_len, payload.network);
    if map.insert(&key, payload.action, 0).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to insert into SUBNET_MATCHING_V4",
        )
            .into_response();
    }
    StatusCode::OK.into_response()
}

pub async fn remove_subnet_matching_v4(
    State(state): State<Arc<RwLock<FirewallState>>>,
    Json(payload): Json<SubnetMatchV4Update>,
) -> impl IntoResponse {
    let state_guard = state.read().await;
    let mut map = state_guard.subnet_matching_v4.write().await;

    let key = Key::new(payload.prefix_len, payload.network);
    if map.remove(&key).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to remove from SUBNET_MATCHING_V4",
        )
            .into_response();
    }
    StatusCode::OK.into_response()
}

pub async fn modify_subnet_matching_v6(
    State(state): State<Arc<RwLock<FirewallState>>>,
    Json(payload): Json<SubnetMatchV6Update>,
) -> impl IntoResponse {
    let state_guard = state.read().await;
    let mut map = state_guard.subnet_matching_v6.write().await;

    let key = Key::new(payload.prefix_len, payload.network);
    if map.insert(&key, payload.action, 0).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to insert into SUBNET_MATCHING_V6",
        )
            .into_response();
    }
    StatusCode::OK.into_response()
}

pub async fn remove_subnet_matching_v6(
    State(state): State<Arc<RwLock<FirewallState>>>,
    Json(payload): Json<SubnetMatchV6Update>,
) -> impl IntoResponse {
    let state_guard = state.read().await;
    let mut map = state_guard.subnet_matching_v6.write().await;

    let key = Key::new(payload.prefix_len, payload.network);
    if map.remove(&key).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to remove from SUBNET_MATCHING_V6",
        )
            .into_response();
    }
    StatusCode::OK.into_response()
}
/// Router for config
pub fn config_router() -> Router<Arc<RwLock<FirewallState>>> {
    Router::new()
        .route("/config", get(get_config).post(update_config))
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
            post(modify_subnet_matching_v4).delete(remove_subnet_matching_v4),
        )
        .route(
            "/subnet/v6",
            post(modify_subnet_matching_v6).delete(remove_subnet_matching_v6),
        )
}
