// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Copyright 2025 MNX Cloud, Inc.

use anyhow::{Context, Result};
use log::{error, info};
use std::path::Path;
use triton_moirai::{
    certificates, configure_haproxy, ensure_haproxy, is_loadbalancer_enabled, mdata_get,
    LOADBALANCER_KEY, REAL_CONFIG_DIR,
};

/// # Triton Moirai - `reconfigure` binary
///
/// This is the main entry point for the Moirai load balancer application.
///
/// ## Functionality
///
/// This program:
///
/// 1. Checks if load balancer is enabled by cloud.tritoncompute:loadbalancer metadata
/// 2. Configures TLS certificates (either Let's Encrypt or self-signed)
/// 3. Generates HAProxy configuration based on service metadata
/// 4. Ensures HAProxy is running with the correct configuration
///
/// ## Environment Variables
///
/// - `RUST_LOG`: Set to `debug` to enable debug output
///
/// ## Usage
///
/// In production environments, this binary is typically installed as
/// `reconfigure` in the triton-moirai deployment. It's executed
/// automatically after container provision and regularly via a cron job.
fn reconfigure() -> Result<()> {
    info!("Triton Moirai - HAProxy based load balancer for Triton");

    // Check if loadbalancer is enabled via metadata
    let loadbalancer_data =
        mdata_get(LOADBALANCER_KEY).context("Failed to get loadbalancer metadata")?;
    let loadbalancer_enabled = is_loadbalancer_enabled(&loadbalancer_data);

    if !loadbalancer_enabled {
        info!("Load balancer is not enabled via metadata. Skipping configuration.");
        return Ok(());
    }

    info!("Load balancer is enabled. Proceeding with configuration.");

    // Configure TLS certificates.
    // We ignore the return value and thus ignore errors and continue
    // no matter what similar to original implementation.
    // TODO: Should we do more than just warn about failures here?
    let _ = certificates::configure_tls();

    // Get path to real config directory
    let real_dir = Path::new(REAL_CONFIG_DIR);

    // Configure HAProxy
    let changed = configure_haproxy(real_dir)?;

    // Ensure HAProxy service is running with the new configuration if it was changed.
    ensure_haproxy(changed)?;

    Ok(())
}

fn main() -> std::process::ExitCode {
    // Initialize logging default to info level
    let env = env_logger::Env::default().filter_or("RUST_LOG", "info");
    env_logger::init_from_env(env);

    // Run the code and exit accordingly
    if let Err(e) = reconfigure() {
        error!("Error: {}", e);
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}
