// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Copyright 2025 MNX Cloud, Inc.

//! # Certificate Management Module
//!
//! This module handles all TLS certificate operations for the triton-moirai load balancer.
//!
//! ## Features
//!
//! The certificate module provides:
//!
//! - Integration with dehydrated for Let's Encrypt certificates
//! - Self-signed certificate generation using OpenSSL
//! - Certificate and symlink management
//! - Logging of certificate operations
//!
//! ## Certificate Types
//!
//! The module handles two types of certificates:
//!
//! 1. **Let's Encrypt certificates**: Obtained via dehydrated when a certificate name
//!    is specified in the `cloud.tritoncompute:certificate_name` metadata.
//!
//! 2. **Self-signed certificates**: Generated automatically when no certificate name
//!    is provided, or when dehydrated is not available.
//!
//! ## Directory Structure
//!
//! The certificates are stored in these standard locations:
//!
//! - `/opt/triton/tls/default/`: Default symlink to the active certificate
//! - `/opt/triton/tls/self-signed/`: Location for self-signed certificates
//! - `/opt/triton/dehydrated/`: Dehydrated working directory

use anyhow::{Context, Result};
use log::{debug, info};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::Command;

use crate::{mdata_get, CERT_NAME_KEY};

// Constants for certificate directories
pub const SELF_SIGNED_CERT_DIR: &str = "/opt/triton/tls/self-signed";
pub const SELF_SIGNED_KEY: &str = "/opt/triton/tls/self-signed/privkey.pem";
pub const SELF_SIGNED_CERT: &str = "/opt/triton/tls/self-signed/cert.pem";
pub const DEFAULT_CERT_DIR: &str = "/opt/triton/tls/default";
pub const DEHYDRATED_DIR: &str = "/opt/triton/dehydrated";

/// Configures TLS certificates based on metadata
///
/// This function:
/// 1. Checks if a certificate name is provided in metadata
/// 2. If yes, configures dehydrated to obtain Let's Encrypt certificates
/// 3. If no, generates a self-signed certificate
///
/// # Returns
///
/// * `Result<bool>` - `true` if certificates were updated, `false` otherwise
pub fn configure_tls() -> Result<bool> {
    // Get certificate subject from metadata
    let cert_subject = match mdata_get(CERT_NAME_KEY) {
        Ok(subject) if !subject.is_empty() => subject,
        _ => {
            // No certificate name present, generate self-signed certificate
            debug!("No certificate name present.");
            return generate_self_signed_certificate();
        }
    };

    info!("Certificate name found: {}", cert_subject);

    // Configure and run dehydrated
    let dehydrated_dir = Path::new(DEHYDRATED_DIR);
    if !dehydrated_dir.exists() {
        return Err(anyhow::anyhow!(
            "Dehydrated directory {} does not exist",
            dehydrated_dir.display()
        ));
    }

    // Create domains.txt file for dehydrated
    let domains_file = dehydrated_dir.join("domains.txt");
    let domains_content = cert_subject.replace(',', " ");
    if domains_file.exists() {
        let current_domains =
            fs::read_to_string(&domains_file).context("Failed to read domains file")?;
        if current_domains.trim() != domains_content.trim() {
            fs::write(&domains_file, domains_content.clone())
                .context("Failed to update domains file")?;
            info!("Updated domains file with: {}", domains_content);
        } else {
            debug!("Domains file already up to date.");
        }
    } else {
        fs::write(&domains_file, domains_content.clone())
            .context("Failed to create domains file")?;
        info!("Created domains file with: {}", domains_content);
    };

    // Run dehydrated to obtain/renew certificates
    let output = Command::new(dehydrated_dir.join("dehydrated"))
        .arg("-c")
        .current_dir(dehydrated_dir)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("Failed to run dehydrated: {}", stderr));
    }

    // Log the dehydrated output
    let log_file = Path::new("/var/log/triton-dehydrated.log");
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)
        .context("Failed to open dehydrated log file")?;

    writeln!(file, "\n--- {} ---", chrono::Local::now())
        .context("Failed to write timestamp to log file")?;
    file.write_all(&output.stdout)
        .context("Failed to write stdout to log file")?;
    file.write_all(&output.stderr)
        .context("Failed to write stderr to log file")?;

    // Check if default cert directory symlink exists and create if needed
    let default_dir = Path::new(DEFAULT_CERT_DIR);
    let parent_dir = default_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Unable to get parent directory of default cert dir"))?;

    // Find a domain directory to link to
    if !default_dir.exists() && !default_dir.is_symlink() {
        let entries =
            fs::read_dir(parent_dir).context("Failed to read SSL certificate directory")?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && path != default_dir {
                // Found a directory to link to
                crate::ensure_cert_symlink(&path, default_dir)?;
                break;
            }
        }
    }

    info!("Certificates were updated.");
    Ok(true)
}

/// Generates a self-signed certificate
///
/// Creates a self-signed certificate if one doesn't already exist
///
/// # Returns
///
/// * `Result<bool>` - `true` if a new certificate was generated, `false` if one already exists
pub fn generate_self_signed_certificate() -> Result<bool> {
    let self_signed_dir = Path::new(SELF_SIGNED_CERT_DIR);
    let privkey_path = Path::new(SELF_SIGNED_KEY);
    let cert_path = Path::new(SELF_SIGNED_CERT);
    let default_dir = Path::new(DEFAULT_CERT_DIR);

    // Check if certificate already exists
    if privkey_path.exists() && cert_path.exists() {
        debug!("Self-signed TLS certificate already exists.");

        // Ensure default symlink exists
        crate::ensure_cert_symlink(self_signed_dir, default_dir)?;

        return Ok(false);
    }

    // Create directory if it doesn't exist
    if !self_signed_dir.exists() {
        fs::create_dir_all(self_signed_dir)?;
    }

    // Create symlink to the self-signed certificate directory
    crate::ensure_cert_symlink(self_signed_dir, default_dir)?;

    info!("Generating TLS self-signed certificate.");

    // Run OpenSSL to generate self-signed certificate
    let output = Command::new("/opt/local/bin/openssl")
        .args([
            "req",
            "-x509",
            "-nodes",
            "-subj",
            "/CN=*",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-pkeyopt",
            "ec_param_enc:named_curve",
            "-newkey",
            "ec",
            "-keyout",
            SELF_SIGNED_KEY,
            "-out",
            SELF_SIGNED_CERT,
            "-days",
            "3650",
        ])
        .output()
        .context("Failed to execute OpenSSL command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!(
            "Failed to generate self-signed certificate: {}",
            stderr
        ));
    }

    // Copy private key to certificate file for HAProxy
    let privkey_content =
        fs::read_to_string(privkey_path).context("Failed to read private key file")?;
    let cert_content = fs::read_to_string(cert_path).context("Failed to read certificate file")?;

    fs::write(cert_path, format!("{}{}", cert_content, privkey_content))
        .context("Failed to write combined certificate file")?;

    // Create fullchain.pem for compatibility with Let's Encrypt cert structure
    let fullchain_path = self_signed_dir.join("fullchain.pem");
    fs::write(
        &fullchain_path,
        format!("{}{}", cert_content, privkey_content),
    )
    .context("Failed to write fullchain.pem file")?;

    info!("Successfully generated self-signed certificate.");
    Ok(true)
}
