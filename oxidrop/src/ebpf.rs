use std::mem;

use anyhow::Context;
use aya::{
    Ebpf,
    maps::{
        Array,
        HashMap,
        LpmTrie,
    },
    programs::{
        Xdp,
        XdpMode,
        xdp::XdpLinkId,
    },
};
use oxidrop_common::{
    AllowListState,
    FirewallConfig,
    TokenBucketState,
};
use tracing::{
    info,
    warn,
};

use crate::Opt;

pub struct EbpfProgramm {
    ebpf: Ebpf,
    /// for shut down or restart
    programm_loaded: Vec<XdpLinkId>,
}
impl EbpfProgramm {
    pub fn new() -> anyhow::Result<EbpfProgramm> {
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
                // This can happen if you remove all log statements from your eBPF program. warn!("failed to initialize eBPF logger: {e}");
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
        let mut self_owned = Self {
            ebpf,
            programm_loaded: Vec::new(),
        };
        let xdp = self_owned.xdp()?;
        xdp.load()?;
        Ok(self_owned)
    }
    fn xdp(&mut self) -> anyhow::Result<&mut Xdp> {
        let xdp: &mut Xdp = self
            .ebpf
            .program_mut("oxidrop")
            .context("getting ebpf failed")?
            .try_into()?;
        Ok(xdp)
    }
    pub fn shut_down_working_ebpf(&mut self) -> anyhow::Result<()> {
        let programm_loaded_taken = mem::take(&mut self.programm_loaded);
        let xdp: &mut Xdp = self.xdp()?;

        for link_id in programm_loaded_taken.into_iter() {
            let _ = xdp.detach(link_id);
        }
        Ok(())
    }
    pub fn reboot(&mut self, config: &FirewallConfig, opt: &Opt) -> anyhow::Result<()> {
        self.shut_down_working_ebpf()?;
        let incoming = opt.incoming_adapter.or(config.incoming_ethernet_adapter);

        if let Some(if_index) = incoming {
            let link_id = {
                let xdp = self.xdp()?;
                let id = xdp.attach_to_if_index(if_index, XdpMode::Default)?;
                info!("XDP program attached to incoming adapter: {}", if_index);
                id
            };
            self.programm_loaded.push(link_id);
        }

        let output = opt.output_adapter.or(config.output_ethernet_adapter);

        if let Some(if_index) = output {
            let link_id = {
                let xdp = self.xdp()?;
                let id = xdp.attach_to_if_index(if_index, XdpMode::Default)?;
                info!("XDP program attached to output adapter: {}", if_index);
                id
            };
            self.programm_loaded.push(link_id);
        }
        Ok(())
    }
    pub fn get_maps(
        &mut self,
    ) -> anyhow::Result<(
        aya::maps::Array<aya::maps::MapData, oxidrop_common::FirewallConfig>,
        aya::maps::HashMap<aya::maps::MapData, oxidrop_common::Ipv4Packet, AllowListState>,
        aya::maps::HashMap<aya::maps::MapData, oxidrop_common::Ipv6Packet, AllowListState>,
        aya::maps::HashMap<aya::maps::MapData, oxidrop_common::Ipv4Packet, TokenBucketState>,
        aya::maps::HashMap<aya::maps::MapData, oxidrop_common::Ipv6Packet, TokenBucketState>,
        aya::maps::LpmTrie<aya::maps::MapData, u32, oxidrop_common::Action>,
        aya::maps::LpmTrie<aya::maps::MapData, [u32; 4], oxidrop_common::Action>,
    )> {
        let ebpf = &mut self.ebpf;
        let config_map: aya::maps::Array<aya::maps::MapData, oxidrop_common::FirewallConfig> =
            Array::try_from(ebpf.take_map("CONFIG").context("CONFIG map not found")?)?;
        let allow_list_v4: aya::maps::HashMap<
            aya::maps::MapData,
            oxidrop_common::Ipv4Packet,
            AllowListState,
        > = HashMap::try_from(
            ebpf.take_map("ALLOW_LIST_V4")
                .context("ALLOW_LIST_V4 map not found")?,
        )?;

        let allow_list_v6: aya::maps::HashMap<
            aya::maps::MapData,
            oxidrop_common::Ipv6Packet,
            AllowListState,
        > = HashMap::try_from(
            ebpf.take_map("ALLOW_LIST_V6")
                .context("ALLOW_LIST_V6 map not found")?,
        )?;

        let packet_counts_v4: aya::maps::HashMap<
            aya::maps::MapData,
            oxidrop_common::Ipv4Packet,
            TokenBucketState,
        > = HashMap::try_from(
            ebpf.take_map("PACKET_COUNTS_V4")
                .context("PACKET_COUNTS_V4 map not found")?,
        )?;

        let packet_counts_v6: aya::maps::HashMap<
            aya::maps::MapData,
            oxidrop_common::Ipv6Packet,
            TokenBucketState,
        > = HashMap::try_from(
            ebpf.take_map("PACKET_COUNTS_V6")
                .context("PACKET_COUNTS_V6 map not found")?,
        )?;

        let subnet_matching_v4: aya::maps::LpmTrie<
            aya::maps::MapData,
            u32,
            oxidrop_common::Action,
        > = LpmTrie::try_from(
            ebpf.take_map("SUBNET_MATCHING_V4")
                .context("SUBNET_MATCHING_V4 map not found")?,
        )?;

        let subnet_matching_v6: aya::maps::LpmTrie<
            aya::maps::MapData,
            [u32; 4],
            oxidrop_common::Action,
        > = LpmTrie::try_from(
            ebpf.take_map("SUBNET_MATCHING_V6")
                .context("SUBNET_MATCHING_V6 map not found")?,
        )?;
        Ok((
            config_map,
            allow_list_v4,
            allow_list_v6,
            packet_counts_v4,
            packet_counts_v6,
            subnet_matching_v4,
            subnet_matching_v6,
        ))
    }
}
