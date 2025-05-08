// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Copyright 2025 MNX Cloud, Inc.

use anyhow::{Context, Result};
use askama::Template;
use log::{debug, error, info, warn};
use std::error::Error as StdError;
use std::fs;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::Path;
use std::process::Command;
use std::str::FromStr;

pub mod certificates;

// Port and backend limits
pub const MIN_PORT: u16 = 1;
pub const MAX_PORT: u16 = 65534;
pub const MAX_BACKENDS_LOW: usize = 32;
pub const MAX_BACKENDS_HIGH: usize = 1024;

// Metadata keys
pub const PORTMAP_KEY: &str = "cloud.tritoncompute:portmap";
pub const MAX_RS_KEY: &str = "cloud.tritoncompute:max_rs";
pub const METRICS_ACL_KEY: &str = "cloud.tritoncompute:metrics_acl";
pub const CERT_NAME_KEY: &str = "cloud.tritoncompute:certificate_name";
pub const LOADBALANCER_KEY: &str = "cloud.tritoncompute:loadbalancer";

// File path constants
pub const FULL_CHAIN_PEM_PATH: &str = "/opt/triton/tls/default/fullchain.pem";
// Path to the actual HAProxy config directory - used by HAProxy service
pub const REAL_CONFIG_DIR: &str = "/opt/local/etc/haproxy.cfg";
// Path to haproxy binary
pub const HAPROXY_BINARY: &str = "/opt/local/sbin/haproxy";

// Embedded HAProxy config files
const HAPROXY_GLOBAL_CFG: &str = include_str!("../templates/000-global.cfg");
const HAPROXY_DEFAULTS_CFG: &str = include_str!("../templates/001-defaults.cfg");
const HAPROXY_RESOLVER_CFG: &str = include_str!("../templates/002-resolver.cfg");

// Path to mdata-get command for illumos
pub const MDATA_GET_PATH: &str = "/usr/sbin/mdata-get";

#[derive(
    strum::Display,
    strum::AsRefStr,
    strum::IntoStaticStr,
    strum::EnumString,
    Debug,
    Hash,
    PartialEq,
    Eq,
)]
#[strum(serialize_all = "lowercase")]
pub enum ServiceType {
    Http,
    Https,
    Httpss,
    Tcp,
}

impl ServiceType {
    // Helper method to determine if service needs SSL configuration
    pub fn mode(&self) -> &ServiceType {
        if matches!(self, ServiceType::Tcp) {
            self
        } else {
            &ServiceType::Http
        }
    }
}

/// Represents a mapping for haproxy from `cloud.tritoncompute:portmap`
/// * `service_type` - Must be one of `http`, `https`, or `tcp`.
///   * `http` - Configures a Layer-7 proxy using the HTTP protocol. The backend
///     server(s) must not use SSL/TLS. `X-Forwarded-For` header will be added to
///     requests.
///   * `https` - Configures a Layer-7 proxy using the HTTP protocol. The backend
///     server(s) must NOT use SSL/TLS.
///     The front end services will use a certificate issued by Let's Encrypt if
///     the `cloud.tritoncompute:certificate_name` metadata key is also provided.
///     Otherwise, a self-signed certificate will be generated. `X-Forwarded-For`
///     header will be added to requests.
///   * `httpss` - Configures a Layer-7 proxy using the HTTP protocol. The backend
///     server(s) must use SSL/TLS. The backend certificate will not be verified.
///     The front end services will use a certificate issued by Let's Encrypt if
///     the `cloud.tritoncompute:certificate_name` metadata key is also provided.
///     Otherwise, a self-signed certificate will be generated. `X-Forwarded-For`
///     header will be added to requests.
///   * `tcp` - Configures a Layer-4 proxy. The backend can use any port. If SSL/TLS
///     is desired, the backend must configure its own certificate.
/// * `listen_port` - This designates the front end listening port.
/// * `backend name` - This is a DNS name that must be resolvable. This **SHOULD**
///   be a CNS name, but can be any fully qualified DNS domain name.
/// * `backend_port` - Optional. This designates the back end port that servers will
///   be listening on. If provided, the back end will be configured to use A record
///   lookups. If a not provided then the back end will be configured to use SRV
///   record lookup. (TODO Need to verify the SRV claim)
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Service {
    pub service_type: ServiceType,
    pub listen_port: u16,
    pub backend_name: String,
    pub backend_port: Option<u16>,
}

impl Service {
    // Helper method to get backend port as a string, empty string if None
    pub fn backend_port_str(&self) -> String {
        match self.backend_port {
            Some(port) => format!(":{}", port),
            None => String::new(),
        }
    }

    // Helper method to determine if service should use sticky sessions
    pub fn use_sticky_session(&self) -> bool {
        matches!(
            self.service_type,
            ServiceType::Http | ServiceType::Https | ServiceType::Httpss
        )
    }

    // Helper method to determine if service needs SSL configuration
    pub fn frontend_ssl(&self) -> bool {
        matches!(self.service_type, ServiceType::Https | ServiceType::Httpss)
    }

    // Helper method to determine if service needs SSL configuration
    pub fn backend_ssl(&self) -> bool {
        matches!(self.service_type, ServiceType::Httpss)
    }

    // Helper method to generate a dynamic_cookie_key
    pub fn dynamic_cookie_key(&self) -> String {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}

impl FromStr for Service {
    type Err = Box<dyn StdError>;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        // Format: <type>://<listen port>:<backend name>[:<backend port>]
        let (service_type, remaining) = parse_service_type(s)?;
        let (listen_port, backend_name, backend_port) = parse_service_parts(remaining)?;

        Ok(Service {
            service_type,
            listen_port,
            backend_name,
            backend_port,
        })
    }
}

/// Parse the service type from the string (first part before "://")
fn parse_service_type(s: &str) -> std::result::Result<(ServiceType, &str), Box<dyn StdError>> {
    s.splitn(2, "://")
        .collect::<Vec<&str>>()
        .as_slice()
        .get(0..2)
        .ok_or_else(|| "Invalid service designation format, missing '://'".into())
        .and_then(|parts| {
            ServiceType::from_str(&parts[0].to_lowercase())
                .map_err(|_| format!("Unsupported protocol: {}", parts[0]).into())
                .map(|service_type| (service_type, parts[1]))
        })
}

/// Parse port and backend information from the string (after "://")
fn parse_service_parts(
    s: &str,
) -> std::result::Result<(u16, String, Option<u16>), Box<dyn StdError>> {
    let parts: Vec<&str> = s.splitn(3, ':').collect();
    if parts.len() < 2 {
        return Err(
            "Invalid service designation format, expecting at least <listen port>:<backend name>"
                .into(),
        );
    }

    let listen_port = parse_and_validate_port(parts[0], "listen")?;
    let backend_port = parts
        .get(2)
        .map(|p| parse_and_validate_port(p, "backend"))
        .transpose()?;

    Ok((listen_port, parts[1].to_string(), backend_port))
}

/// Parse a port string and validate that it's within allowed range
fn parse_and_validate_port(
    port_str: &str,
    port_type: &str,
) -> std::result::Result<u16, Box<dyn StdError>> {
    port_str
        .parse::<u16>()
        .map_err(|_| format!("Invalid {} port: {}", port_type, port_str).into())
        .and_then(|port| {
            if (MIN_PORT..=MAX_PORT).contains(&port) {
                Ok(port)
            } else {
                Err(format!(
                    "{} port out of valid range ({}-{}): {}",
                    port_type, MIN_PORT, MAX_PORT, port_str
                )
                .into())
            }
        })
}

#[derive(Template)]
#[template(path = "100-services.cfg.jinja")]
pub struct Portmap {
    pub services: Vec<Service>,
    pub max_backends: usize,
}

/// Template for metrics configuration
#[derive(Template)]
#[template(path = "200-metrics.cfg.jinja")]
pub struct MetricsConfig {
    pub use_ssl: bool,
}

/// Struct to track services that couldn't be parsed or validated
#[derive(Debug)]
pub struct RejectedService {
    pub string: String,
    pub errors: Vec<String>,
}

/// Parse a comma or space-separated list of service designations into a vector of Services
///
/// Parses and validates each service designation in the input string and returns
/// both a list of valid services and a list of rejected services with their errors.
///
/// # Returns
///
/// A tuple containing:
/// * A vector of successfully parsed `Service` objects
/// * A vector of `RejectedService` objects with errors for invalid entries
pub fn parse_services(input: &str) -> (Vec<Service>, Vec<RejectedService>) {
    input
        .split([',', ' '])
        .filter(|s| !s.is_empty())
        .map(|s| s.trim().replace('\n', ""))
        .filter(|s| !s.is_empty())
        .fold(
            (Vec::new(), Vec::new()),
            |(mut services, mut rejected), cleaned_str| {
                match Service::from_str(&cleaned_str) {
                    Ok(service) => services.push(service),
                    Err(err) => rejected.push(RejectedService {
                        string: cleaned_str,
                        errors: vec![err.to_string()],
                    }),
                };
                (services, rejected)
            },
        )
}

/// Parse the max_rs metadata value and apply constraints
///
/// Parses the input string as a usize and ensures the value is within the
/// allowed range (MAX_BACKENDS_LOW to MAX_BACKENDS_HIGH).
///
/// # Returns
///
/// The validated max_backends value, clamped to the allowed range
pub fn parse_max_rs(input: &str) -> usize {
    input
        .trim()
        .parse::<usize>()
        .unwrap_or(MAX_BACKENDS_LOW)
        .clamp(MAX_BACKENDS_LOW, MAX_BACKENDS_HIGH)
}

/// Checks if the cloud.tritoncompute:loadbalancer metadata is set to "true"
/// Returns a boolean indicating if the loadbalancer flag is enabled
pub fn is_loadbalancer_enabled(input: &str) -> bool {
    input.trim().eq_ignore_ascii_case("true")
}

/// Get metadata for a given key using mdata-get command
///
/// Executes the system mdata-get command to retrieve container metadata.
/// Returns empty string on any errors including command failure or
/// if the key doesn't exist.
///
/// TODO: add a timeout here.
pub fn mdata_get(key: &str) -> Result<String> {
    // Use the system mdata-get command
    match Command::new(MDATA_GET_PATH).arg(key).output() {
        Ok(output) if output.status.success() => {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        }
        Err(e) => {
            error!(
                "mdata-get error: running {MDATA_GET_PATH} returned {:#?}",
                e
            );
            Ok(String::new())
        }
        Ok(_) => Ok(String::new()),
    }
}

/// Create a symlink for certificates, ensuring parent directories exist
pub fn ensure_cert_symlink(source: &Path, target: &Path) -> Result<bool> {
    if target.exists() || target.is_symlink() {
        return Ok(false);
    }

    if let Some(parent) = target.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }

    use std::os::unix::fs as unix_fs;
    unix_fs::symlink(source, target)?;
    info!(
        "Created symlink from {} to {}.",
        source.display(),
        target.display()
    );
    Ok(true)
}

/// Compare two directories to check if their contents are identical
///
/// Uses the diff -r command to compare directory contents
///
/// # Arguments
///
/// * `dir1` - First directory path to compare
/// * `dir2` - Second directory path to compare
///
/// # Returns
///
/// * `Result<bool>` - True if directories are identical, false otherwise
pub fn dirs_equal(dir1: &Path, dir2: &Path) -> Result<bool> {
    let output = Command::new("/usr/bin/diff")
        .arg("-r")
        .arg(dir1)
        .arg(dir2)
        .output()
        .with_context(|| {
            format!(
                "Failed to compare directories: {} and {}",
                dir1.display(),
                dir2.display()
            )
        })?;

    Ok(output.status.success())
}

/// Validate the HAProxy configuration
///
/// Uses the HAProxy binary with the -c flag to check if the configuration
/// syntax is valid without actually starting the service.
///
/// # Arguments
///
/// * `config_dir` - Directory containing the HAProxy configuration
///
/// # Returns
///
/// * `Result<(bool, String)>` - Returns success status and the command output
pub fn validate_haproxy_config(config_dir: &Path) -> Result<(bool, String)> {
    let output = Command::new(HAPROXY_BINARY)
        .arg("-c")
        .arg("-f")
        .arg(config_dir)
        .output()
        .context("Failed to execute haproxy validation command")?;

    let combined_output = format!(
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    Ok((output.status.success(), combined_output))
}

/// Configure ACL for metrics access
///
/// This function:
/// 1. Retrieves metrics ACL data from metadata
/// 2. Writes the ACL to a file
/// 3. Creates the metrics frontend configuration if ACL is not empty
///
/// # Arguments
///
/// * `config_dir` - The directory where HAProxy configuration files will be written
///
/// # Returns
///
/// * `Result<bool>` - Returns true if metrics config was created, false otherwise
pub fn configure_acl(config_dir: &Path) -> Result<bool> {
    let acl_file_path = config_dir.join("210-metrics_acl.txt");

    // Get metrics ACL data and process it
    let acl_data = mdata_get(METRICS_ACL_KEY)?;
    if acl_data.is_empty() {
        return Ok(false); // No ACL data, return early
    }

    // Convert spaces and commas to newlines (one IP or subnet per line)
    let formatted_acl = acl_data
        .split([',', ' '])
        .filter(|s| !s.is_empty())
        .collect::<Vec<&str>>()
        .join("\n");

    // Write ACL data to file
    fs::write(&acl_file_path, &formatted_acl).context("Failed to write ACL data to file")?;

    // Check if ACL file has content
    if formatted_acl.is_empty() {
        fs::remove_file(acl_file_path).context("Failed to remove empty ACL file")?;
        return Ok(false);
    }

    // Create metrics configuration
    let use_ssl = Path::new(FULL_CHAIN_PEM_PATH).exists();
    let metrics_config = MetricsConfig { use_ssl };
    let rendered_config = metrics_config
        .render()
        .context("Failed to render metrics configuration template")?;

    // Write rendered config to file
    fs::write(config_dir.join("200-metrics.cfg"), rendered_config)
        .context("Failed to write metrics configuration file")?;

    Ok(true)
}

/// Configure HAProxy by generating and applying a new configuration
///
/// This function:
/// 1. Creates a temporary config directory
/// 2. Writes the embedded config files directly
/// 3. Generates the service configuration
/// 4. Configures metrics ACL if needed
/// 5. Compares with the existing configuration
/// 6. Validates and applies the new configuration if different
///
/// # Arguments
///
/// * `real_dir` - Directory where the live HAProxy config is located
///
/// # Returns
///
/// * `Result<bool>` - Returns true if the configuration was changed, false otherwise
pub fn configure_haproxy(real_dir: &Path) -> Result<bool> {
    // Create temporary directory for candidate config
    let temp_dir =
        tempfile::tempdir().context("Failed to create temporary directory for config")?;
    let candidate_dir = temp_dir.path();

    // Create destination directory if it doesn't exist
    fs::create_dir_all(candidate_dir).context("Failed to create destination directory")?;

    // Write embedded HAProxy config files directly
    fs::write(candidate_dir.join("000-global.cfg"), HAPROXY_GLOBAL_CFG)
        .context("Failed to write global config file")?;
    fs::write(candidate_dir.join("001-defaults.cfg"), HAPROXY_DEFAULTS_CFG)
        .context("Failed to write defaults config file")?;
    fs::write(candidate_dir.join("002-resolver.cfg"), HAPROXY_RESOLVER_CFG)
        .context("Failed to write resolver config file")?;

    // Get portmap metadata
    let portmap_data = mdata_get(PORTMAP_KEY).context("Failed to get portmap metadata")?;
    debug!("mDataString: {:#?}", portmap_data.clone());

    // Parse the portmap metadata
    let (services, rejected) = parse_services(&portmap_data);

    // Log validation results
    debug!("ignored services:\n{:#?}", &rejected);
    debug!("valid services:\n{:#?}", &services);

    // Get max_rs metadata
    let max_rs_data = mdata_get(MAX_RS_KEY).context("Failed to get max_rs metadata")?;
    let max_backends = parse_max_rs(&max_rs_data);

    // Create portmap configuration
    let portmap = Portmap {
        services,
        max_backends,
    };

    // Render the HAProxy configuration
    let rendered_config = portmap
        .render()
        .context("Failed to render HAProxy configuration template")?;

    // Write the rendered services config
    let services_cfg_path = candidate_dir.join("100-services.cfg");
    fs::write(&services_cfg_path, &rendered_config)
        .context("Failed to write services configuration file")?;

    // Configure metrics ACL
    let _metrics_configured =
        configure_acl(candidate_dir).context("Failed to configure metrics ACL")?;

    // Compare configs to see if there's a difference
    if dirs_equal(real_dir, candidate_dir).context("Failed to compare config directories")? {
        debug!("HAProxy configuration is unchanged.");
        return Ok(false);
    }

    // Config is different, validate it
    let (is_valid, validation_output) = validate_haproxy_config(candidate_dir)
        .context("Failed to validate HAProxy configuration")?;
    if is_valid {
        // Create or ensure the real config directory exists
        fs::create_dir_all(real_dir).context("Failed to create real config directory")?;

        // Get all files from the candidate directory
        let entries = fs::read_dir(candidate_dir).context("Failed to read candidate directory")?;

        // Copy each file to the real config directory
        for entry in entries.flatten() {
            let src_path = entry.path();
            if src_path.is_file() {
                let file_name = src_path.file_name().unwrap(); // Safe as we know it's a file
                let dst_path = real_dir.join(file_name);

                // Read source file content
                let content = fs::read(&src_path)
                    .context(format!("Failed to read file: {}", src_path.display()))?;

                // Write to destination
                fs::write(&dst_path, content)
                    .context(format!("Failed to write file: {}", dst_path.display()))?;
            }
        }

        // Remove any files in real_dir that aren't in candidate_dir
        let real_entries =
            fs::read_dir(real_dir).context("Failed to read real config directory")?;

        for real_entry in real_entries.flatten() {
            let real_path = real_entry.path();
            if real_path.is_file() {
                let file_name = real_path.file_name().unwrap();
                let candidate_path = candidate_dir.join(file_name);

                if !candidate_path.exists() {
                    fs::remove_file(&real_path)
                        .context(format!("Failed to remove file: {}", real_path.display()))?;
                }
            }
        }

        info!("HAProxy configuration was updated.");
        Ok(true)
    } else {
        warn!("Candidate config is invalid, keeping current configuration.");
        warn!("HAProxy validation output: {}", validation_output);
        println!("{}", rendered_config);
        Ok(false)
    }
}

/// Restart a service using SMF
pub fn restart_service(service: &str) {
    debug!("Checking service status for: {}", service);

    // Create a service pattern
    let fmri_pattern = vec![service];

    // Get the service information through the Query API
    let query_result = smf::Query::new().get_status(smf::QuerySelection::ByPattern(&fmri_pattern));

    match query_result {
        Ok(services) => {
            let services_vec: Vec<_> = services.collect();

            if services_vec.is_empty() {
                warn!("Service '{}' not found, skipping.", service);
                return;
            }

            let service_status = &services_vec[0];
            debug!("Service state: {:?}", service_status.state);

            if service_status.state == smf::SmfState::Online {
                info!("Restarting {}...", service);

                // Use SMF crate to restart the service
                let result = smf::Adm::new()
                    .restart()
                    .run(smf::AdmSelection::ByPattern(&fmri_pattern));

                match result {
                    Ok(_) => debug!("Service restart completed."),
                    Err(e) => error!("Failed to restart service {}: {}", service, e),
                }
            } else {
                debug!("Service '{}' is not online, skipping.", service);
            }
        }
        Err(e) => {
            error!("Failed to check service status: {}", e);
        }
    }
}

/// Check and manage the state of the HAProxy service
///
/// This function:
/// 1. Checks the current state of the HAProxy service
/// 2. Takes appropriate action based on that state
/// 3. For online services with config changes, performs a graceful restart
///
/// # Arguments
///
/// * `config_changed` - Whether the configuration has changed
///
/// # Returns
///
/// * `Result<()>` - Success or an error
pub fn ensure_haproxy(config_changed: bool) -> Result<()> {
    // Get HAProxy service state using SMF crate
    // Create a service pattern for HAProxy
    let fmri_pattern = vec!["haproxy"];

    // Get the service information through the Query API
    let query_result = smf::Query::new()
        .get_status(smf::QuerySelection::ByPattern(&fmri_pattern))
        .context("Failed to query HAProxy service state")?;

    let services: Vec<_> = query_result.collect();
    if services.is_empty() {
        return Err(anyhow::anyhow!("HAProxy service not found"));
    }

    let service = &services[0];
    info!("HAProxy state: {}", service.state.to_string());

    match service.state {
        smf::SmfState::Disabled => {
            // Enable the service using SMF crate
            info!("Enabling HAProxy service...");

            // Create an adm object and configure it for enabling a service
            smf::Adm::new()
                .enable()
                .synchronous() // Wait for service to come online
                .run(smf::AdmSelection::ByPattern(&fmri_pattern))
                .context("Failed to enable HAProxy service")?;
        }
        smf::SmfState::Maintenance => {
            // Clear the service using SMF crate
            info!("Clearing HAProxy service from maintenance state...");

            // Create an adm object and configure it for clearing a service
            smf::Adm::new()
                .clear()
                .run(smf::AdmSelection::ByPattern(&fmri_pattern))
                .context("Failed to clear HAProxy service from maintenance state")?;
        }
        smf::SmfState::Online => {
            if config_changed {
                if let Some(ctid) = service.contract_id {
                    info!("Gracefully restarting HAProxy (container ID: {})...", ctid);

                    // Gracefully restart HAProxy with USR2 signal
                    // We still need to use the Command for this specialized restart
                    let ctid_str = ctid.to_string();
                    let _ = Command::new("pkill")
                        .args(["-USR2", "-c", &ctid_str, "haproxy"])
                        .status();

                    // Note: We ignore errors from pkill, following original script behavior
                } else {
                    // If for some reason we can't get the ctid, do a regular restart
                    warn!("No container ID found, performing regular restart...");
                    let _ = smf::Adm::new()
                        .restart()
                        .run(smf::AdmSelection::ByPattern(&fmri_pattern));
                }
            }
        }
        _ => {
            // TODO Should this be an error?
            warn!("HAProxy non-actionable state: {:?}", service.state);
        }
    }

    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_dirs_equal() {
        // Create two temporary directories for testing
        let dir1 = tempfile::tempdir().expect("Failed to create temp directory 1");
        let dir2 = tempfile::tempdir().expect("Failed to create temp directory 2");

        // Initially they should be equal (both empty)
        let equal = dirs_equal(dir1.path(), dir2.path()).expect("Failed to compare directories");
        assert!(equal, "Empty directories should be equal");

        // Create a file in dir1
        let file_path = dir1.path().join("test.txt");
        fs::write(&file_path, "test content").expect("Failed to write file");

        // Now they should not be equal
        let equal = dirs_equal(dir1.path(), dir2.path()).expect("Failed to compare directories");
        assert!(
            !equal,
            "Directories with different content should not be equal"
        );

        // Create the same file in dir2
        let file_path2 = dir2.path().join("test.txt");
        fs::write(&file_path2, "test content").expect("Failed to write file");

        // Now they should be equal again
        let equal = dirs_equal(dir1.path(), dir2.path()).expect("Failed to compare directories");
        assert!(equal, "Directories with same content should be equal");
    }

    #[test]
    fn test_is_loadbalancer_enabled() {
        // Test with exact match
        assert!(
            is_loadbalancer_enabled("true"),
            "Should be enabled for 'true'"
        );

        // Test with case variations
        assert!(
            is_loadbalancer_enabled("TRUE"),
            "Should be enabled for 'TRUE'"
        );
        assert!(
            is_loadbalancer_enabled("True"),
            "Should be enabled for 'True'"
        );
        assert!(
            is_loadbalancer_enabled("tRuE"),
            "Should be enabled for 'tRuE'"
        );

        // Test with whitespace
        assert!(
            is_loadbalancer_enabled(" true "),
            "Should be enabled with whitespace"
        );

        // Test with false values
        assert!(
            !is_loadbalancer_enabled("false"),
            "Should not be enabled for 'false'"
        );
        assert!(
            !is_loadbalancer_enabled(""),
            "Should not be enabled for empty string"
        );
        assert!(
            !is_loadbalancer_enabled("1"),
            "Should not be enabled for '1'"
        );
        assert!(
            !is_loadbalancer_enabled("yes"),
            "Should not be enabled for 'yes'"
        );
    }

    #[test]
    fn test_parse_services() {
        let test_data = "tcp://12345:service_name.svc.account_uuid.datacenter.cns.domain.zone:23456,httpss://443:tlswebthing.svc.account_uuid.datacenter.cns.domain.zone:5443,tcp://80:webthing.svc.account_uuid.datacenter.cns.domain.zone:31799";

        // Parse the test data into a vector of services
        let (services, rejected) = parse_services(test_data);

        // Verify there are no rejected services
        assert_eq!(rejected.len(), 0);

        // Verify the number of services parsed
        assert_eq!(services.len(), 3);

        // Verify the first service
        assert_eq!(services[0].service_type.to_string(), "tcp");
        assert_eq!(services[0].listen_port, 12345);
        assert_eq!(
            services[0].backend_name,
            "service_name.svc.account_uuid.datacenter.cns.domain.zone"
        );
        assert_eq!(services[0].backend_port, Some(23456));

        // Verify the second service
        assert_eq!(services[1].service_type.to_string(), "httpss");
        assert_eq!(services[1].listen_port, 443);
        assert_eq!(
            services[1].backend_name,
            "tlswebthing.svc.account_uuid.datacenter.cns.domain.zone"
        );
        assert_eq!(services[1].backend_port, Some(5443));

        // Verify the third service
        assert_eq!(services[2].service_type.to_string(), "tcp");
        assert_eq!(services[2].listen_port, 80);
        assert_eq!(
            services[2].backend_name,
            "webthing.svc.account_uuid.datacenter.cns.domain.zone"
        );
        assert_eq!(services[2].backend_port, Some(31799));
    }

    #[test]
    fn test_parse_max_rs() {
        // Test with empty string - should use the default (MAX_BACKENDS_LOW)
        assert_eq!(parse_max_rs(""), MAX_BACKENDS_LOW);

        // Test with non-numeric value - should use the default
        assert_eq!(parse_max_rs("not a number"), MAX_BACKENDS_LOW);

        // Test with value below the minimum - should be capped at MIN
        assert_eq!(parse_max_rs("10"), MAX_BACKENDS_LOW);

        // Test with value within range
        assert_eq!(parse_max_rs("128"), 128);

        // Test with value above the maximum - should be capped at MAX
        assert_eq!(parse_max_rs("2048"), MAX_BACKENDS_HIGH);
    }

    #[test]
    fn test_parse_services_with_invalid() {
        let test_data = "tcp://12345:service_name.svc.account_uuid.datacenter.cns.domain.zone:23456,invalid://443:something,tcp://99999:invalid_port";

        // Parse the test data into a vector of services
        let (services, rejected) = parse_services(test_data);

        // Verify valid and rejected service counts
        assert_eq!(services.len(), 1);
        assert_eq!(rejected.len(), 2);

        // Verify rejected services contain appropriate errors
        assert!(rejected[0].errors[0].contains("Unsupported protocol"));

        // Debug print the actual error message for the second rejected service
        println!("Invalid port error message: {}", rejected[1].errors[0]);
        assert!(
            rejected[1].errors[0].contains("Invalid")
                || rejected[1].errors[0].contains("valid range")
        );
    }

    #[test]
    fn test_portmap_rendering() {
        let test_data = "tcp://12345:service_name.svc.account_uuid.datacenter.cns.domain.zone:23456,httpss://443:tlswebthing.svc.account_uuid.datacenter.cns.domain.zone:5443,tcp://80:webthing.svc.account_uuid.datacenter.cns.domain.zone:31799";
        let (services, _) = parse_services(test_data);

        // Create a Portmap with the parsed services
        let portmap = Portmap {
            services,
            max_backends: MAX_BACKENDS_LOW,
        };

        // Render the template with the parsed services
        let rendered = portmap.render().expect("Failed to render template");

        // Check that the rendered template is exactly what we expect
        let expected = r#"#                                                  #
# ## DO NOT EDIT. THIS FILE WILL BE OVERWRITTEN ## #
#                                                  #

frontend fe0
	mode tcp
	bind *:12345
	default_backend be0

backend be0
	mode tcp
	server-template rs 32 service_name.svc.account_uuid.datacenter.cns.domain.zone:23456 check resolvers system init-addr none

frontend fe1
	mode http
	bind *:443 ssl crt /opt/triton/tls/default/fullchain.pem
	default_backend be1

backend be1
	mode http
	cookie CLOUD-TRITONCOMPUTE-RS insert indirect nocache dynamic
	dynamic-cookie-key 8cfd5654b73fd64d
	server-template rs 32 tlswebthing.svc.account_uuid.datacenter.cns.domain.zone:5443 ssl verify none check resolvers system init-addr none

frontend fe2
	mode tcp
	bind *:80
	default_backend be2

backend be2
	mode tcp
	server-template rs 32 webthing.svc.account_uuid.datacenter.cns.domain.zone:31799 check resolvers system init-addr none
"#;
        assert_eq!(rendered, expected)
    }

    #[test]
    fn test_portmap_rendering_with_https() {
        // Create a test service with HTTPS protocol on frontend only
        let services = vec![Service {
            service_type: ServiceType::Https,
            listen_port: 443,
            backend_name: "some-app.svc.account_uuid.datacenter.cns.domain.zone".to_string(),
            backend_port: Some(8080),
        }];

        // Create a Portmap with the parsed services
        let portmap = Portmap {
            services,
            max_backends: MAX_BACKENDS_LOW,
        };

        // Render the template with the parsed services
        let rendered = portmap.render().expect("Failed to render template");

        // Check that the rendered template includes SSL configuration
        let expected = r#"#                                                  #
# ## DO NOT EDIT. THIS FILE WILL BE OVERWRITTEN ## #
#                                                  #

frontend fe0
	mode http
	bind *:443 ssl crt /opt/triton/tls/default/fullchain.pem
	default_backend be0

backend be0
	mode http
	cookie CLOUD-TRITONCOMPUTE-RS insert indirect nocache dynamic
	dynamic-cookie-key c3a0bdf5617a40b6
	server-template rs 32 some-app.svc.account_uuid.datacenter.cns.domain.zone:8080 check resolvers system init-addr none
"#;
        assert_eq!(rendered, expected)
    }

    #[test]
    fn test_portmap_rendering_with_httpss() {
        // Create a test service with HTTPS protocol on both sides
        let services = vec![Service {
            service_type: ServiceType::Httpss,
            listen_port: 443,
            backend_name: "secure-app.svc.account_uuid.datacenter.cns.domain.zone".to_string(),
            backend_port: Some(8443),
        }];

        // Create a Portmap with the parsed services
        let portmap = Portmap {
            services,
            max_backends: MAX_BACKENDS_LOW,
        };

        // Render the template with the parsed services
        let rendered = portmap.render().expect("Failed to render template");

        // Check that the rendered template includes SSL configuration
        let expected = r#"#                                                  #
# ## DO NOT EDIT. THIS FILE WILL BE OVERWRITTEN ## #
#                                                  #

frontend fe0
	mode http
	bind *:443 ssl crt /opt/triton/tls/default/fullchain.pem
	default_backend be0

backend be0
	mode http
	cookie CLOUD-TRITONCOMPUTE-RS insert indirect nocache dynamic
	dynamic-cookie-key 2c110ee8e1fed00b
	server-template rs 32 secure-app.svc.account_uuid.datacenter.cns.domain.zone:8443 ssl verify none check resolvers system init-addr none
"#;
        assert_eq!(rendered, expected)
    }

    #[test]
    fn test_portmap_rendering_with_http() {
        // Create a test service with HTTP protocol
        let services = vec![Service {
            service_type: ServiceType::Http,
            listen_port: 80,
            backend_name: "web-app.svc.account_uuid.datacenter.cns.domain.zone".to_string(),
            backend_port: Some(8080),
        }];

        // Create a Portmap with the parsed services
        let portmap = Portmap {
            services,
            max_backends: MAX_BACKENDS_LOW,
        };

        // Render the template with the parsed services
        let rendered = portmap.render().expect("Failed to render template");

        // Check that the rendered template includes sticky session but no SSL
        let expected = r#"#                                                  #
# ## DO NOT EDIT. THIS FILE WILL BE OVERWRITTEN ## #
#                                                  #

frontend fe0
	mode http
	bind *:80
	default_backend be0

backend be0
	mode http
	cookie CLOUD-TRITONCOMPUTE-RS insert indirect nocache dynamic
	dynamic-cookie-key 55a2dd978d410d9c
	server-template rs 32 web-app.svc.account_uuid.datacenter.cns.domain.zone:8080 check resolvers system init-addr none
"#;
        assert_eq!(rendered, expected)
    }

    #[test]
    fn test_portmap_rendering_with_none() {
        // Create a test service with None backend_port
        let services = vec![Service {
            service_type: ServiceType::Tcp,
            listen_port: 636,
            backend_name: "my-backend.svc.my-login.us-west-1.cns.example.com".to_string(),
            backend_port: None,
        }];

        // Create a Portmap with the parsed services
        let portmap = Portmap {
            services,
            max_backends: MAX_BACKENDS_HIGH,
        };

        // Render the template with the parsed services
        let rendered = portmap.render().expect("Failed to render template");

        // Check that the rendered template correctly handles None values
        let expected = format!(
            r#"#                                                  #
# ## DO NOT EDIT. THIS FILE WILL BE OVERWRITTEN ## #
#                                                  #

frontend fe0
	mode tcp
	bind *:636
	default_backend be0

backend be0
	mode tcp
	server-template rs {0} my-backend.svc.my-login.us-west-1.cns.example.com check resolvers system init-addr none
"#,
            MAX_BACKENDS_HIGH
        );
        assert_eq!(rendered, expected)
    }

    #[test]
    fn test_error_handling() {
        // Test with a service with invalid port
        let test_data = "tcp://0:too_small_port:12345";
        let (services, rejected) = parse_services(test_data);

        assert_eq!(services.len(), 0);
        assert_eq!(rejected.len(), 1);

        // Debug print the actual error message
        println!("Too small port error message: {}", rejected[0].errors[0]);
        assert!(
            rejected[0].errors[0].contains("valid range")
                || rejected[0].errors[0].contains("out of")
        );

        // Test with multiple errors
        let test_data = "invalid://123:backend,tcp://99999:too_big_port";
        let (services, rejected) = parse_services(test_data);

        assert_eq!(services.len(), 0);
        assert_eq!(rejected.len(), 2);
        assert!(rejected[0].errors[0].contains("Unsupported protocol"));

        // Debug print the actual error message for the second rejected service
        println!("Too big port error message: {}", rejected[1].errors[0]);
        assert!(
            rejected[1].errors[0].contains("Invalid")
                || rejected[1].errors[0].contains("valid range")
        );
    }

    #[test]
    fn test_parse_case_insensitive_protocol() {
        // Test parsing case-insensitive protocol strings
        let test_data = "TcP://22:ssh.service.com:2222,HttP://80:web.service.com:8080,hTTps://443:secure.service.com:8443";

        // Parse the test data into a vector of services
        let (services, rejected) = parse_services(test_data);

        // Verify there are no rejected services and 3 valid ones
        assert_eq!(rejected.len(), 0);
        assert_eq!(services.len(), 3);

        // Verify protocol normalization
        assert_eq!(services[0].service_type.to_string(), "tcp");
        assert_eq!(services[1].service_type.to_string(), "http");
        assert_eq!(services[2].service_type.to_string(), "https");
    }

    #[test]
    fn test_metrics_config_rendering_with_ssl() {
        // Test metrics config with SSL enabled
        let metrics_config = MetricsConfig { use_ssl: true };
        let rendered = metrics_config
            .render()
            .expect("Failed to render metrics config");
        let expected = r#"#                                                  #
# ## DO NOT EDIT. THIS FILE WILL BE OVERWRITTEN ## #
#                                                  #
frontend __cloud_tritoncompute__metrics
  bind *:8405 ssl crt /opt/triton/tls/default/fullchain.pem
  mode http
  http-request deny if !{ src -f 210-metrics_acl.txt }
  http-request use-service prometheus-exporter if { path /metrics }
  no log
"#;
        assert_eq!(rendered, expected);
    }

    #[test]
    fn test_metrics_config_rendering_without_ssl() {
        // Test metrics config without SSL
        let metrics_config = MetricsConfig { use_ssl: false };
        let rendered = metrics_config
            .render()
            .expect("Failed to render metrics config");
        let expected = r#"#                                                  #
# ## DO NOT EDIT. THIS FILE WILL BE OVERWRITTEN ## #
#                                                  #
frontend __cloud_tritoncompute__metrics
  bind *:8405
  mode http
  http-request deny if !{ src -f 210-metrics_acl.txt }
  http-request use-service prometheus-exporter if { path /metrics }
  no log
"#;
        assert_eq!(rendered, expected);
    }
}
