use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use ldap3::{
    LdapConnAsync, LdapConnSettings, Ldap, Scope, SearchEntry,
};
use std::collections::HashSet;
use std::pin::Pin;
use std::future::Future;
use crate::models::{ADUser, ADGroup, GroupType, GroupScope, UserRight, RightSource};

pub struct LdapClient {
    ldap: Ldap,
    base_dn: String,
}

impl LdapClient {
    pub async fn connect(
        server: &str,
        use_tls: bool,
    ) -> Result<Self> {
        let ldap_url = if use_tls {
            format!("ldaps://{}:636", server)
        } else {
            format!("ldap://{}:389", server)
        };

        let settings = LdapConnSettings::new();
        let (conn, mut ldap) = LdapConnAsync::with_settings(
            settings,
            &ldap_url,
        ).await
            .context("Failed to connect to LDAP server")?;

        ldap3::drive!(conn);

        // Get base DN from rootDSE (proper way to discover naming context)
        let base_dn = Self::get_base_dn_from_rootdse(&mut ldap)
            .await
            .unwrap_or_else(|_| Self::extract_base_dn(server));

        Ok(Self {
            ldap,
            base_dn,
        })
    }


    /// Bind using GSSAPI/Kerberos authentication (Windows integrated)
    /// Requires:
    /// - Windows domain-joined machine
    /// - Valid Kerberos ticket (automatically obtained)
    /// - Server FQDN (not IP address or short hostname)
    pub async fn bind_gssapi(&mut self, server_fqdn: &str) -> Result<()> {
        #[cfg(windows)]
        {
            // Perform SASL GSSAPI bind using current user's Kerberos credentials
            self.ldap
                .sasl_gssapi_bind(server_fqdn)
                .await
                .context(
                    "GSSAPI bind failed. This usually indicates:\n\
                     1. Server FQDN is incorrect (provide full domain name, not IP)\n\
                     2. Machine is not domain-joined\n\
                     3. Kerberos ticket unavailable (reboot or use 'kinit' on Unix)\n\
                     4. Service Principal Name (SPN) not registered in AD\n\
                     5. Network connectivity to domain controller lost"
                )?
                .success()
                .context("GSSAPI bind authentication failed")?;
            Ok(())
        }
        #[cfg(not(windows))]
        {
            Err(anyhow::anyhow!(
                "GSSAPI/Kerberos authentication requires:\n\
                 - Windows platform\n\
                 - Domain-joined machine\n\
                 - Proper SPN registration in Active Directory\n\n\
                 Alternative: Use explicit credentials with --username and --password options"
            ))
        }
    }

    /// Bind using simple authentication (username/password)
    /// Fallback for non-Windows platforms or when GSSAPI is unavailable
    pub async fn bind_simple(&mut self, username: &str, password: &str) -> Result<()> {
        self.ldap
            .simple_bind(username, password)
            .await
            .context("Failed to connect for simple bind")?
            .success()
            .context("Simple bind authentication failed")?;
        Ok(())
    }

    pub async fn get_user(&mut self, username: &str) -> Result<ADUser> {
        // Search for user
        let filter = format!("(&(objectClass=user)(sAMAccountName={}))", username);
        let attributes = vec![
            "distinguishedName",
            "sAMAccountName",
            "userPrincipalName",
            "displayName",
            "mail",
            "department",
            "title",
            "description",
            "userAccountControl",
            "lastLogonTimestamp",
            "whenCreated",
            "whenChanged",
            "memberOf",
            "primaryGroupID",
        ];

        let (rs, _res) = self.ldap
            .search(
                &self.base_dn,
                Scope::Subtree,
                &filter,
                attributes,
            )
            .await
            .context("Failed to search for user")?
            .success()
            .context("User search failed")?;

        let entry = rs
            .into_iter()
            .next()
            .context("User not found")?;
        
        let search_entry = SearchEntry::construct(entry);
        
        // Parse user attributes
        let mut user = ADUser::new(
            search_entry.dn.clone(),
            Self::get_attr(&search_entry, "sAMAccountName")
                .unwrap_or_else(|| username.to_string()),
        );

        // Populate user fields
        user.user_principal_name = Self::get_attr(&search_entry, "userPrincipalName");
        user.display_name = Self::get_attr(&search_entry, "displayName");
        user.email = Self::get_attr(&search_entry, "mail");
        user.department = Self::get_attr(&search_entry, "department");
        user.title = Self::get_attr(&search_entry, "title");
        user.description = Self::get_attr(&search_entry, "description");

        // Parse User Account Control flags
        if let Some(uac_str) = Self::get_attr(&search_entry, "userAccountControl") {
            if let Ok(uac) = uac_str.parse::<u32>() {
                user.account_enabled = (uac & 0x2) == 0; // ADS_UF_ACCOUNTDISABLE
                user.account_locked = (uac & 0x10) != 0; // ADS_UF_LOCKOUT
                user.password_expired = (uac & 0x800000) != 0; // ADS_UF_PASSWORD_EXPIRED
                user.password_never_expires = (uac & 0x10000) != 0; // ADS_UF_DONT_EXPIRE_PASSWD
            }
        }

        // Parse timestamps
        user.last_logon = Self::parse_ad_timestamp(
            Self::get_attr(&search_entry, "lastLogonTimestamp").as_deref()
        );
        user.created = Self::parse_ldap_timestamp(
            Self::get_attr(&search_entry, "whenCreated").as_deref()
        );
        user.modified = Self::parse_ldap_timestamp(
            Self::get_attr(&search_entry, "whenChanged").as_deref()
        );

        // Get group memberships
        let member_of = search_entry.attrs
            .get("memberOf")
            .cloned()
            .unwrap_or_default();
        
        let mut processed_groups = HashSet::new();
        for group_dn in member_of {
            if let Ok(group) = self.get_group_recursive(&group_dn, &mut processed_groups).await {
                user.groups.push(group);
            }
        }

        // Get primary group
        if let Some(primary_group_id) = Self::get_attr(&search_entry, "primaryGroupID") {
            if let Ok(primary_group) = self.get_primary_group(&primary_group_id).await {
                user.primary_group = Some(primary_group);
            }
        }

        // Populate user rights based on group memberships
        user.user_rights = self.determine_user_rights(&user);

        Ok(user)
    }

    fn get_group_recursive<'a>(
        &'a mut self,
        group_dn: &'a str,
        processed: &'a mut HashSet<String>,
    ) -> Pin<Box<dyn Future<Output = Result<ADGroup>> + 'a>> {
        Box::pin(async move {
            if processed.contains(group_dn) {
                return Err(anyhow::anyhow!("Circular group reference detected"));
            }
            processed.insert(group_dn.to_string());

            let attributes = vec![
                "distinguishedName",
                "cn",
                "description",
                "groupType",
                "memberOf",
            ];

            let (rs, _res) = self.ldap
                .search(
                    group_dn,
                    Scope::Base,
                    "(objectClass=group)",
                    attributes,
                )
                .await
                .context("Failed to search for group")?
                .success()
                .context("Group search failed")?;

            let entry = rs
                .into_iter()
                .next()
                .context("Group not found")?;
            
            let search_entry = SearchEntry::construct(entry);
            
            let mut group = ADGroup::new(
                search_entry.dn.clone(),
                Self::get_attr(&search_entry, "cn")
                    .unwrap_or_else(|| "Unknown".to_string()),
            );

            group.description = Self::get_attr(&search_entry, "description");

            // Parse group type
            if let Some(gt_str) = Self::get_attr(&search_entry, "groupType") {
                if let Ok(gt) = gt_str.parse::<i32>() {
                    group.group_type = if (gt & 0x80000000u32 as i32) != 0 {
                        GroupType::Security
                    } else {
                        GroupType::Distribution
                    };

                    group.scope = match gt & 0x7 {
                        2 => GroupScope::Global,
                        4 => GroupScope::DomainLocal,
                        8 => GroupScope::Universal,
                        _ => GroupScope::Global,
                    };
                }
            }

            // Get nested groups
            if let Some(member_of) = search_entry.attrs.get("memberOf") {
                for nested_dn in member_of {
                    if let Ok(nested_group) = self.get_group_recursive(nested_dn, processed).await {
                        group.nested_groups.push(nested_group);
                    }
                }
            }

            Ok(group)
        })
    }

    async fn get_primary_group(&mut self, primary_group_id: &str) -> Result<ADGroup> {
        // Convert primary group ID to RID and search for group
        // This is a simplified implementation
        let filter = format!("(&(objectClass=group)(primaryGroupToken={}))", primary_group_id);
        
        let (rs, _res) = self.ldap
            .search(
                &self.base_dn,
                Scope::Subtree,
                &filter,
                vec!["distinguishedName", "cn", "description"],
            )
            .await
            .context("Failed to search for primary group")?
            .success()
            .context("Primary group search failed")?;

        let entry = rs
            .into_iter()
            .next()
            .context("Primary group not found")?;
        
        let search_entry = SearchEntry::construct(entry);
        
        let mut group = ADGroup::new(
            search_entry.dn.clone(),
            Self::get_attr(&search_entry, "cn")
                .unwrap_or_else(|| "Domain Users".to_string()),
        );
        
        group.description = Self::get_attr(&search_entry, "description");
        
        Ok(group)
    }

    fn determine_user_rights(&self, user: &ADUser) -> Vec<UserRight> {
        let mut rights = Vec::new();
        
        // Check for common administrative groups
        for group in user.all_groups() {
            let source = RightSource::GroupMembership(group.name.clone());
            
            if group.name.contains("Domain Admins") {
                rights.push(UserRight {
                    name: "Full Domain Administration".to_string(),
                    description: "Complete control over the domain".to_string(),
                    source: source.clone(),
                });
            }
            
            if group.name.contains("Enterprise Admins") {
                rights.push(UserRight {
                    name: "Enterprise Administration".to_string(),
                    description: "Administrative access across the forest".to_string(),
                    source: source.clone(),
                });
            }
            
            if group.name.contains("Schema Admins") {
                rights.push(UserRight {
                    name: "Schema Modification".to_string(),
                    description: "Can modify Active Directory schema".to_string(),
                    source: source.clone(),
                });
            }
            
            if group.name.contains("Account Operators") {
                rights.push(UserRight {
                    name: "Account Management".to_string(),
                    description: "Can create and manage user accounts".to_string(),
                    source: source.clone(),
                });
            }
            
            if group.name.contains("Server Operators") {
                rights.push(UserRight {
                    name: "Server Management".to_string(),
                    description: "Can manage domain servers".to_string(),
                    source: source.clone(),
                });
            }
            
            if group.name.contains("Backup Operators") {
                rights.push(UserRight {
                    name: "Backup Rights".to_string(),
                    description: "Can backup and restore files".to_string(),
                    source: source.clone(),
                });
            }
            
            if group.name.contains("Remote Desktop Users") {
                rights.push(UserRight {
                    name: "Remote Desktop Access".to_string(),
                    description: "Can log on through Remote Desktop Services".to_string(),
                    source: source.clone(),
                });
            }
        }

        rights
    }

    fn get_attr(entry: &SearchEntry, attr: &str) -> Option<String> {
        entry.attrs
            .get(attr)
            .and_then(|v| v.first())
            .cloned()
    }

    /// Query rootDSE to get the proper base DN (naming context)
    async fn get_base_dn_from_rootdse(ldap: &mut Ldap) -> Result<String> {
        // Query rootDSE (empty DN with base scope)
        let (rs, _res) = ldap
            .search(
                "",
                Scope::Base,
                "(objectClass=*)",
                vec!["defaultNamingContext"],
            )
            .await
            .context("Failed to query rootDSE")?
            .success()
            .context("rootDSE query failed")?;

        let entry = rs
            .into_iter()
            .next()
            .context("rootDSE entry not found")?;

        let search_entry = SearchEntry::construct(entry);

        Self::get_attr(&search_entry, "defaultNamingContext")
            .context("defaultNamingContext not found in rootDSE")
    }

    fn extract_base_dn(server: &str) -> String {
        // Fallback: Simple extraction - assumes last two domain parts are the base
        // e.g., "HRWDCAZ02.htgb.handt.co.uk" -> only use the domain parts after the hostname
        let parts: Vec<&str> = server.split('.').collect();

        // Skip the first part (hostname) if there are more than 2 parts
        let domain_parts = if parts.len() > 2 {
            &parts[1..]
        } else {
            &parts
        };

        let dc_parts: Vec<String> = domain_parts.iter().map(|p| format!("DC={}", p)).collect();
        dc_parts.join(",")
    }

    fn parse_ad_timestamp(timestamp: Option<&str>) -> Option<DateTime<Utc>> {
        timestamp.and_then(|ts| {
            ts.parse::<i64>().ok().and_then(|ticks| {
                // AD timestamp is in 100-nanosecond intervals since 1601-01-01
                let unix_ticks = ticks - 116444736000000000i64;
                let seconds = unix_ticks / 10000000;
                DateTime::from_timestamp(seconds, 0)
            })
        })
    }

    fn parse_ldap_timestamp(timestamp: Option<&str>) -> Option<DateTime<Utc>> {
        timestamp.and_then(|ts| {
            // LDAP timestamp format: YYYYMMDDHHmmSS.0Z
            chrono::NaiveDateTime::parse_from_str(
                &ts.replace(".0Z", ""),
                "%Y%m%d%H%M%S"
            ).ok()
            .map(|dt| DateTime::from_naive_utc_and_offset(dt, Utc))
        })
    }
}