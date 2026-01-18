use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ADUser {
    pub distinguished_name: String,
    pub sam_account_name: String,
    pub user_principal_name: Option<String>,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub department: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub account_enabled: bool,
    pub account_locked: bool,
    pub password_expired: bool,
    pub password_never_expires: bool,
    pub last_logon: Option<DateTime<Utc>>,
    pub created: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub groups: Vec<ADGroup>,
    pub primary_group: Option<ADGroup>,
    pub user_rights: Vec<UserRight>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ADGroup {
    pub distinguished_name: String,
    pub name: String,
    pub description: Option<String>,
    pub group_type: GroupType,
    pub scope: GroupScope,
    pub nested_groups: Vec<ADGroup>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GroupType {
    Security,
    Distribution,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GroupScope {
    DomainLocal,
    Global,
    Universal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRight {
    pub name: String,
    pub description: String,
    pub source: RightSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RightSource {
    DirectAssignment,
    GroupMembership(String), // Group name that grants this right
    Default,
}

#[derive(Debug, Clone)]
pub struct ReportData {
    pub user: ADUser,
    pub generation_time: DateTime<Utc>,
    pub domain_name: String,
    pub domain_controller: String,
}

impl ADUser {
    pub fn new(dn: String, sam: String) -> Self {
        Self {
            distinguished_name: dn,
            sam_account_name: sam,
            user_principal_name: None,
            display_name: None,
            email: None,
            department: None,
            title: None,
            description: None,
            account_enabled: true,
            account_locked: false,
            password_expired: false,
            password_never_expires: false,
            last_logon: None,
            created: None,
            modified: None,
            groups: Vec::new(),
            primary_group: None,
            user_rights: Vec::new(),
        }
    }

    pub fn all_groups(&self) -> Vec<&ADGroup> {
        let mut all_groups = Vec::new();
        
        if let Some(primary) = &self.primary_group {
            all_groups.push(primary);
        }
        
        for group in &self.groups {
            Self::collect_groups(group, &mut all_groups);
        }
        
        all_groups
    }

    fn collect_groups<'a>(group: &'a ADGroup, collection: &mut Vec<&'a ADGroup>) {
        collection.push(group);
        for nested in &group.nested_groups {
            Self::collect_groups(nested, collection);
        }
    }
}

impl ADGroup {
    pub fn new(dn: String, name: String) -> Self {
        Self {
            distinguished_name: dn,
            name,
            description: None,
            group_type: GroupType::Security,
            scope: GroupScope::Global,
            nested_groups: Vec::new(),
        }
    }
}