use std::sync::Arc;

use axum::{
    Json,
    Router,
    extract::State,
    routing::get,
};
use aya::maps::{
    Array,
    HashMap,
    LpmTrie,
    MapData,
};
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
    pub incoming_ethernet_adapter: Option<Option<usize>>,
    #[serde(default)]
    pub output_ethernet_adapter: Option<Option<usize>>,
}

/// get config from the firewall
pub async fn get_config(State(state): State<Arc<RwLock<FirewallState>>>) -> Json<FirewallConfig> {
    let config_map = {
        let state_guard = state.read().await;
        state_guard.config.clone()
    };

    let cfg = config_map
        .read()
        .await
        .get(&0, 0)
        .expect("CONFIG map not initialized");
    Json(cfg)
}

/// update firewall config
pub async fn update_config(
    State(state): State<Arc<RwLock<FirewallState>>>,
    Json(patch): Json<ConfigPatch>,
) -> Json<FirewallConfig> {
    let config_map = {
        let state_guard = state.read().await;
        state_guard.config.clone()
    };

    let mut map = config_map.write().await;
    let mut cfg = map.get(&0, 0).expect("CONFIG map not initialized");

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
        cfg.incoming_ethernet_adapter = adapter;
    }
    if let Some(adapter) = patch.output_ethernet_adapter {
        cfg.output_ethernet_adapter = adapter;
    }

    map.set(0, cfg, 0).expect("Failed to update CONFIG map");

    Json(cfg)
}
/// Router for config
pub fn config_router() -> Router<Arc<RwLock<FirewallState>>> {
    Router::new().route("/config", get(get_config).post(update_config))
}
