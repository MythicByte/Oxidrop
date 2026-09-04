use std::sync::Arc;

use axum::{
    Json,
    Router,
    extract::State,
    response::IntoResponse,
    routing::get,
};
use aya::maps::{
    Array,
    HashMap,
    LpmTrie,
    MapData,
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
/// Router for config
pub fn config_router() -> Router<Arc<RwLock<FirewallState>>> {
    Router::new().route("/config", get(get_config).post(update_config))
}
