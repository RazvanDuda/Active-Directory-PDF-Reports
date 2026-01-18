use anyhow::Result;
use tracing::{info, warn, error};

/// Diagnostics for troubleshooting Kerberos/GSSAPI authentication issues
pub struct Diagnostics;

impl Diagnostics {
    /// Run comprehensive pre-flight checks for GSSAPI authentication
    pub fn run_preflight_checks(server: &str) -> Result<()> {
        info!("Running GSSAPI authentication preflight checks...\n");

        // Check 1: Platform support
        Self::check_platform();

        // Check 2: Domain-joined status (Windows)
        #[cfg(windows)]
        Self::check_domain_joined();

        // Check 3: Server FQDN validation
        Self::check_server_fqdn(server);

        // Check 4: Environment variables
        #[cfg(windows)]
        Self::check_environment_variables();

        // Check 5: Network connectivity (basic)
        #[cfg(windows)]
        Self::check_network_connectivity(server);

        info!("Preflight checks completed.\n");
        Ok(())
    }

    /// Check platform support for GSSAPI
    fn check_platform() {
        info!("✓ Platform Check:");
        #[cfg(windows)]
        {
            info!("  Running on Windows - GSSAPI/Kerberos supported");
        }
        #[cfg(not(windows))]
        {
            warn!("  Not running on Windows - GSSAPI/Kerberos not available");
            info!("  On Unix/Linux: Use explicit credentials (-u, -p) or configure Kerberos");
        }
        info!("");
    }

    /// Check if machine is domain-joined (Windows)
    #[cfg(windows)]
    fn check_domain_joined() {
        info!("✓ Domain Status Check:");
        match (std::env::var("USERDOMAIN"), std::env::var("USERDNSDOMAIN")) {
            (Ok(domain), Ok(dns_domain)) => {
                info!("  Domain: {} ({})", domain, dns_domain);
                info!("  ✓ Machine appears to be domain-joined");
            }
            _ => {
                warn!("  Unable to detect domain membership");
                warn!("  Machine may not be domain-joined");
                warn!("  Ensure this is a domain-joined Windows machine");
            }
        }
        info!("");
    }

    /// Validate server FQDN format
    fn check_server_fqdn(server: &str) {
        info!("✓ Server FQDN Validation:");
        info!("  Server: {}", server);

        if server.contains('.') {
            info!("  ✓ Server appears to be fully qualified (contains domain)");
        } else if server.contains("\\\\") || server.starts_with("\\\\") {
            warn!("  Server appears to be a UNC path (\\\\server)");
            warn!("  Use FQDN format instead: ad.company.com");
        } else {
            warn!("  Server does not appear to be fully qualified");
            warn!("  GSSAPI requires FQDN (e.g., 'ad.company.com', not 'ad-server')");
            warn!("  Short hostnames and IP addresses will not work with GSSAPI");
        }

        // Check for IP address
        if server.chars().all(|c| c.is_numeric() || c == '.') {
            error!("  ✗ Server appears to be an IP address");
            error!("  GSSAPI authentication REQUIRES the server's FQDN");
            error!("  Kerberos cannot authenticate to IP addresses");
        }

        info!("");
    }

    /// Check environment variables (Windows)
    #[cfg(windows)]
    fn check_environment_variables() {
        info!("✓ Environment Variables:");

        let username = std::env::var("USERNAME").ok();
        let userdomain = std::env::var("USERDOMAIN").ok();
        let userdnsdomain = std::env::var("USERDNSDOMAIN").ok();
        let logonserver = std::env::var("LOGONSERVER").ok();

        if let (Some(u), Some(d)) = (username, userdomain) {
            info!("  Current User: {}\\{}", d, u);
        } else {
            warn!("  Could not determine current user");
        }

        if let Some(dns) = userdnsdomain {
            info!("  DNS Domain: {}", dns);
        } else {
            warn!("  USERDNSDOMAIN not set (may affect GSSAPI)");
        }

        if let Some(logon) = logonserver {
            let cleaned = logon.trim_start_matches("\\\\");
            info!("  Logon Server: {}", cleaned);
        }

        info!("");
    }

    /// Basic network connectivity check
    #[cfg(windows)]
    fn check_network_connectivity(server: &str) {
        info!("✓ Network Connectivity Check:");
        info!("  Attempting to validate server reachability...");

        // Try to parse as hostname
        match server.parse::<std::net::IpAddr>() {
            Ok(_) => {
                // It's an IP - try to connect
                if let Ok(addrs) = std::net::ToSocketAddrs::to_socket_addrs(&format!(
                    "{}:389",
                    server
                )) {
                    if addrs.collect::<Vec<_>>().is_empty() {
                        warn!("  Could not resolve server address");
                    } else {
                        info!("  ✓ Server appears reachable on LDAP port (389)");
                    }
                } else {
                    warn!("  Could not resolve server address");
                }
            }
            Err(_) => {
                // It's a hostname - try DNS lookup
                match std::net::ToSocketAddrs::to_socket_addrs(&format!(
                    "{}:389",
                    server
                )) {
                    Ok(addrs) => {
                        let addrs_vec: Vec<_> = addrs.collect();
                        if addrs_vec.is_empty() {
                            warn!("  Could not resolve server hostname: {}", server);
                            warn!("  Verify DNS resolution: nslookup {}", server);
                        } else {
                            info!("  ✓ Server resolved: {}", server);
                            if let Some(addr) = addrs_vec.first() {
                                info!("    IP: {}", addr.ip());
                            }
                        }
                    }
                    Err(_) => {
                        warn!("  Could not resolve server: {}", server);
                        warn!("  Check DNS configuration and verify server FQDN");
                    }
                }
            }
        }

        info!("");
    }

    /// Display troubleshooting guidance
    pub fn show_troubleshooting_guide() {
        info!("\n=== GSSAPI/Kerberos Troubleshooting Guide ===\n");

        info!("Common Issues and Solutions:\n");

        info!("1. \"FQDN is incorrect\" or SPN-related errors:");
        info!("   - Use the server's fully qualified domain name (FQDN)");
        info!("   - Example: ad.company.com (NOT ad-server or 192.168.1.10)");
        info!("   - Verify: nslookup <server_fqdn>");
        info!("");

        info!("2. \"Machine is not domain-joined\":");
        info!("   - Only domain-joined Windows machines can use GSSAPI");
        info!("   - Verify: Settings > System > About > Check domain status");
        info!("   - Use --username and --password for non-domain machines");
        info!("");

        info!("3. \"Kerberos ticket unavailable\":");
        info!("   - Kerberos tickets may expire");
        info!("   - Windows (command): gpupdate /force");
        info!("   - Windows: Restart the computer");
        info!("   - Or use explicit credentials: --username and --password");
        info!("");

        info!("4. \"SPN not registered in Active Directory\":");
        info!("   - LDAP service SPN may not be registered");
        info!("   - Requires Active Directory administrator to verify/register");
        info!("   - Workaround: Use --username and --password");
        info!("");

        info!("5. \"Cannot reach domain controller\":");
        info!("   - Verify network connectivity to AD server");
        info!("   - Check firewall rules (LDAP port 389/636)");
        info!("   - Verify DNS resolution: nslookup <server_fqdn>");
        info!("");

        info!("6. \"Clock skew\" or time-related errors:");
        info!("   - Kerberos is sensitive to time synchronization");
        info!("   - Sync system clock: Settings > Time & Language > Sync now");
        info!("   - Should be within 5 minutes of domain controller");
        info!("");

        info!("Alternative: Use Explicit Credentials");
        info!("   If GSSAPI doesn't work, use simple bind:");
        info!("   ad-report -s <server> -u domain\\username -p password -t <target_user>");
        info!("");
    }

    /// Display current authentication method info
    pub fn show_auth_info() {
        info!("Authentication Configuration:");
        #[cfg(all(windows, feature = "gssapi"))]
        {
            info!("✓ GSSAPI/Kerberos support: ENABLED");
            info!("  Use --use-gssapi to authenticate with current Windows user");
        }
        #[cfg(not(all(windows, feature = "gssapi")))]
        {
            info!("ℹ GSSAPI/Kerberos support: NOT AVAILABLE");
            info!("  (Requires Windows platform and 'gssapi' feature)");
        }
        info!("✓ Simple authentication: ALWAYS AVAILABLE");
        info!("  Use --username and --password for explicit credentials");
    }
}
