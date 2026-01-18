use anyhow::{Context, Result};

/// Windows authentication helper for GSSAPI/Kerberos authentication
pub struct WindowsAuth;

impl WindowsAuth {
    /// Check if Kerberos integrated authentication is available on this platform
    pub fn is_available() -> bool {
        #[cfg(windows)]
        {
            // Check if we're running on a domain-joined Windows machine
            std::env::var("USERDOMAIN").is_ok() && std::env::var("USERNAME").is_ok()
        }
        #[cfg(not(windows))]
        {
            false
        }
    }

    /// Get current Windows user information
    pub fn get_current_user() -> Result<(String, String)> {
        #[cfg(windows)]
        {
            let username = std::env::var("USERNAME")
                .context("Failed to get current username from environment")?;
            let domain = std::env::var("USERDOMAIN")
                .context("Failed to get current user domain from environment")?;
            Ok((domain, username))
        }
        #[cfg(not(windows))]
        {
            Err(anyhow::anyhow!(
                "Kerberos integrated authentication is only available on Windows platforms"
            ))
        }
    }

    /// Get the current user's domain
    pub fn get_current_domain() -> Option<String> {
        #[cfg(windows)]
        {
            std::env::var("USERDOMAIN").ok()
        }
        #[cfg(not(windows))]
        {
            None
        }
    }

    /// Get the current user's full DN format (DOMAIN\username)
    pub fn get_current_user_dn() -> Result<String> {
        let (domain, username) = Self::get_current_user()?;
        Ok(format!("{}\\{}", domain, username))
    }

    /// Get the current user's UPN format (username@domain)
    pub fn get_current_user_upn() -> Result<String> {
        let (domain, username) = Self::get_current_user()?;
        let dns_domain = std::env::var("USERDNSDOMAIN")
            .unwrap_or_else(|_| domain.to_lowercase());
        Ok(format!("{}@{}", username, dns_domain))
    }

    /// Get default LDAP server from Windows environment
    pub fn get_default_ldap_server() -> Option<String> {
        #[cfg(windows)]
        {
            // Try to get domain controller from LOGONSERVER
            std::env::var("LOGONSERVER").ok()
                .map(|server| server.trim_start_matches("\\\\").to_string())
                .or_else(|| {
                    // Fallback: use DNS domain as server
                    std::env::var("USERDNSDOMAIN").ok()
                })
        }
        #[cfg(not(windows))]
        {
            None
        }
    }

    /// Validate that the server FQDN can be resolved
    pub fn validate_server_dns(server: &str) -> Result<String> {
        // For DNS resolution, we could use dns-lookup crate
        // For now, validate that it's a proper FQDN (contains at least one dot)
        if server.contains('.') {
            Ok(server.to_string())
        } else {
            Err(anyhow::anyhow!(
                "Server '{}' does not appear to be a fully qualified domain name (FQDN). \
                 GSSAPI authentication requires the server's FQDN (e.g., 'ad.company.com'). \
                 Please provide the correct FQDN.",
                server
            ))
        }
    }
}

/// Helper function to determine if we should attempt Kerberos authentication
pub fn should_use_gssapi(username: &Option<String>, use_gssapi_flag: bool) -> bool {
    if !use_gssapi_flag {
        return false;
    }

    // Use GSSAPI if:
    // 1. Explicitly requested AND
    // 2. Platform supports it (Windows currently)
    WindowsAuth::is_available()
}

/// Helper function to get the default LDAP server
pub fn get_default_ldap_server() -> Option<String> {
    WindowsAuth::get_default_ldap_server()
}