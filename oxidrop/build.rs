use std::{
    env,
    path::PathBuf,
    process::Command,
};

use anyhow::{
    Context as _,
    anyhow,
};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "oxidrop-ebpf")
        .ok_or_else(|| anyhow!("oxidrop-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], Toolchain::default())?;

    // frontend fresh build
    // Find the frontend directory relative to the current crate (oxidrop)
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").context("CARGO_MANIFEST_DIR not set")?;
    let frontend_dir = PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .join("frontend");

    // Execute `deno task build` in the frontend directory
    let status = Command::new("deno")
        .arg("task")
        .arg("build")
        .current_dir(&frontend_dir)
        .status()
        .context("Failed to execute 'deno task build'")?;

    if !status.success() {
        return Err(anyhow!("Frontend build failed with exit status: {status}"));
    }
    Ok(())
}
