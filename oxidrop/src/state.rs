use std::sync::Arc;

use aya::maps::{
    Array,
    HashMap,
    LpmTrie,
    MapData,
};
use oxidrop_common::{
    Action,
    AllowListState,
    FirewallConfig,
    Ipv4Packet,
    Ipv6Packet,
    TokenBucketState,
};
use tokio::sync::RwLock;

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
