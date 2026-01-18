use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use crate::models::{ADUser, ADGroup, UserRight, RightSource};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionOverlap {
    pub permission: String,
    pub description: String,
    pub granting_groups: Vec<String>,
    pub overlap_type: OverlapType,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OverlapType {
    Duplicate,        // Same permission from multiple groups
    Escalation,       // Permission that grants higher privileges when combined
    Redundant,        // Unnecessary permission due to inheritance
    Conflicting,      // Permissions that might conflict with each other
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone)]
pub struct OverlapAnalysis {
    pub overlaps: Vec<PermissionOverlap>,
    pub total_permissions: usize,
    pub overlapped_permissions: usize,
    pub redundancy_score: f32,
    pub risk_summary: RiskSummary,
}

#[derive(Debug, Clone)]
pub struct RiskSummary {
    pub critical_overlaps: usize,
    pub high_overlaps: usize,
    pub medium_overlaps: usize,
    pub low_overlaps: usize,
    pub most_dangerous_combinations: Vec<String>,
}

pub struct PermissionAnalyzer;

impl PermissionAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Analyze permission overlaps for a user
    pub fn analyze_overlaps(&self, user: &ADUser) -> OverlapAnalysis {
        let permission_map = self.build_permission_map(user);
        let overlaps = self.detect_overlaps(&permission_map);
        let risk_summary = self.calculate_risk_summary(&overlaps);
        
        let total_permissions = permission_map.len();
        let overlapped_permissions = overlaps.len();
        let redundancy_score = if total_permissions > 0 {
            (overlapped_permissions as f32 / total_permissions as f32) * 100.0
        } else {
            0.0
        };

        OverlapAnalysis {
            overlaps,
            total_permissions,
            overlapped_permissions,
            redundancy_score,
            risk_summary,
        }
    }

    /// Build a map of permissions to their granting sources
    fn build_permission_map(&self, user: &ADUser) -> HashMap<String, Vec<String>> {
        let mut permission_map: HashMap<String, Vec<String>> = HashMap::new();
        
        // Add permissions from all groups (direct and nested)
        for group in user.all_groups() {
            let group_permissions = self.get_group_permissions(&group.name);
            for permission in group_permissions {
                permission_map
                    .entry(permission)
                    .or_insert_with(Vec::new)
                    .push(group.name.clone());
            }
        }

        // Add direct user rights
        for right in &user.user_rights {
            let source = match &right.source {
                RightSource::DirectAssignment => "Direct Assignment".to_string(),
                RightSource::GroupMembership(group) => group.clone(),
                RightSource::Default => "Default".to_string(),
            };
            
            permission_map
                .entry(right.name.clone())
                .or_insert_with(Vec::new)
                .push(source);
        }

        permission_map
    }

    /// Detect overlapping permissions
    fn detect_overlaps(&self, permission_map: &HashMap<String, Vec<String>>) -> Vec<PermissionOverlap> {
        let mut overlaps = Vec::new();

        for (permission, sources) in permission_map {
            if sources.len() > 1 {
                let overlap_type = self.determine_overlap_type(permission, sources);
                let risk_level = self.assess_permission_risk(permission, sources, &overlap_type);
                let description = self.get_permission_description(permission);

                overlaps.push(PermissionOverlap {
                    permission: permission.clone(),
                    description,
                    granting_groups: sources.clone(),
                    overlap_type,
                    risk_level,
                });
            }
        }

        // Sort by risk level (highest first)
        overlaps.sort_by(|a, b| a.risk_level.cmp(&b.risk_level));
        overlaps
    }

    /// Determine the type of overlap
    fn determine_overlap_type(&self, permission: &str, sources: &[String]) -> OverlapType {
        // Check for dangerous escalation combinations
        if self.is_escalation_permission(permission) && sources.len() > 2 {
            return OverlapType::Escalation;
        }

        // Check for conflicting permissions
        if self.has_conflicting_sources(sources) {
            return OverlapType::Conflicting;
        }

        // Check for redundant permissions due to inheritance
        if self.is_redundant_permission(permission, sources) {
            return OverlapType::Redundant;
        }

        // Default to duplicate
        OverlapType::Duplicate
    }

    /// Assess the risk level of a permission overlap
    fn assess_permission_risk(&self, permission: &str, sources: &[String], overlap_type: &OverlapType) -> RiskLevel {
        // Critical risk permissions
        if self.is_critical_permission(permission) {
            return RiskLevel::Critical;
        }

        // High risk based on overlap type
        match overlap_type {
            OverlapType::Escalation => return RiskLevel::High,
            OverlapType::Conflicting if sources.len() > 3 => return RiskLevel::High,
            _ => {}
        }

        // High risk based on permission type
        if self.is_high_risk_permission(permission) {
            return RiskLevel::High;
        }

        // Medium risk for administrative permissions
        if self.is_admin_permission(permission) {
            return RiskLevel::Medium;
        }

        RiskLevel::Low
    }

    /// Calculate risk summary from overlaps
    fn calculate_risk_summary(&self, overlaps: &[PermissionOverlap]) -> RiskSummary {
        let mut critical_overlaps = 0;
        let mut high_overlaps = 0;
        let mut medium_overlaps = 0;
        let mut low_overlaps = 0;
        let mut dangerous_combinations = HashSet::new();

        for overlap in overlaps {
            match overlap.risk_level {
                RiskLevel::Critical => {
                    critical_overlaps += 1;
                    dangerous_combinations.insert(format!(
                        "{} ({})", 
                        overlap.permission, 
                        overlap.granting_groups.join(", ")
                    ));
                }
                RiskLevel::High => {
                    high_overlaps += 1;
                    if overlap.granting_groups.len() > 2 {
                        dangerous_combinations.insert(format!(
                            "{} ({})", 
                            overlap.permission, 
                            overlap.granting_groups.join(", ")
                        ));
                    }
                }
                RiskLevel::Medium => medium_overlaps += 1,
                RiskLevel::Low => low_overlaps += 1,
            }
        }

        RiskSummary {
            critical_overlaps,
            high_overlaps,
            medium_overlaps,
            low_overlaps,
            most_dangerous_combinations: dangerous_combinations.into_iter().take(5).collect(),
        }
    }

    /// Get permissions granted by a specific group
    fn get_group_permissions(&self, group_name: &str) -> Vec<String> {
        // This would normally query a permission database or AD
        // Enhanced to handle custom business groups with intelligent pattern matching
        let name_lower = group_name.to_lowercase();
        
        match group_name {
            // Built-in Windows AD groups
            name if name.contains("Domain Admins") => vec![
                "Full Domain Control".to_string(),
                "User Management".to_string(),
                "Computer Management".to_string(),
                "Group Policy Management".to_string(),
                "Schema Modification".to_string(),
                "Directory Service Access".to_string(),
            ],
            name if name.contains("Enterprise Admins") => vec![
                "Forest-wide Administration".to_string(),
                "Schema Modification".to_string(),
                "Configuration Container Access".to_string(),
                "Cross-Domain Access".to_string(),
            ],
            name if name.contains("Schema Admins") => vec![
                "Schema Modification".to_string(),
                "Directory Schema Access".to_string(),
            ],
            name if name.contains("Account Operators") => vec![
                "User Account Management".to_string(),
                "Group Management".to_string(),
                "OU Management".to_string(),
            ],
            name if name.contains("Server Operators") => vec![
                "Server Management".to_string(),
                "Service Management".to_string(),
                "Backup/Restore Operations".to_string(),
            ],
            name if name.contains("Backup Operators") => vec![
                "Backup Operations".to_string(),
                "Restore Operations".to_string(),
                "File System Access".to_string(),
            ],
            name if name.contains("Print Operators") => vec![
                "Print Queue Management".to_string(),
                "Printer Administration".to_string(),
            ],
            name if name.contains("Remote Desktop Users") => vec![
                "Remote Desktop Access".to_string(),
                "Interactive Logon Rights".to_string(),
            ],
            name if name.contains("Power Users") => vec![
                "System Configuration".to_string(),
                "Application Installation".to_string(),
                "Performance Monitoring".to_string(),
            ],
            
            // Enhanced patterns for custom business groups
            name if name_lower.contains("admin") || name_lower.contains("administrator") => vec![
                "Administrative Access".to_string(),
                "System Configuration".to_string(),
                "User Management".to_string(),
                if name_lower.contains("database") || name_lower.contains("db") { "Database Administration".to_string() } else { "General Administration".to_string() },
            ],
            
            name if name_lower.contains("database") || name_lower.contains("db") => vec![
                "Database Access".to_string(),
                "Data Query Rights".to_string(),
                if name_lower.contains("reporting") { "Database Reporting".to_string() } else { "Database Operations".to_string() },
                if name_lower.contains("rw") || name_lower.contains("write") { "Database Write Access".to_string() } else { "Database Read Access".to_string() },
            ],
            
            name if name_lower.contains("developer") || name_lower.contains("dev") => vec![
                "Development Environment Access".to_string(),
                "Code Repository Access".to_string(),
                "Application Deployment".to_string(),
                if name_lower.contains("prod") { "Production Environment Access".to_string() } else { "Development Tools".to_string() },
            ],
            
            name if name_lower.contains("it") && (name_lower.contains("user") || name_lower.contains("staff")) => vec![
                "IT Administrative Tools".to_string(),
                "System Monitoring".to_string(),
                "Technical Support Access".to_string(),
                "Infrastructure Management".to_string(),
            ],
            
            name if name_lower.contains("reporting") || name_lower.contains("report") => vec![
                "Report Generation".to_string(),
                "Data Analysis Access".to_string(),
                "Business Intelligence".to_string(),
            ],
            
            name if name_lower.contains("vpn") => vec![
                "VPN Access".to_string(),
                "Remote Network Access".to_string(),
                "Secure Connectivity".to_string(),
            ],
            
            name if name_lower.contains("ssl") || name_lower.contains("cert") => vec![
                "Certificate Management".to_string(),
                "SSL/TLS Administration".to_string(),
                "Security Infrastructure".to_string(),
            ],
            
            name if name_lower.contains("print") || name_lower.contains("printer") => vec![
                "Printer Access".to_string(),
                "Print Queue Management".to_string(),
                "Document Processing".to_string(),
            ],
            
            name if name_lower.contains("backup") || name_lower.contains("restore") => vec![
                "Backup Operations".to_string(),
                "Data Recovery".to_string(),
                "Archive Management".to_string(),
            ],
            
            name if name_lower.contains("breakglass") || name_lower.contains("emergency") => vec![
                "Emergency Access".to_string(),
                "Break-Glass Privileges".to_string(),
                "Critical System Access".to_string(),
            ],
            
            name if name_lower.contains("uat") || name_lower.contains("test") => vec![
                "Test Environment Access".to_string(),
                "Quality Assurance".to_string(),
                "Pre-Production Access".to_string(),
            ],
            
            name if name_lower.contains("office") || name_lower.contains("location") => vec![
                "Physical Location Access".to_string(),
                "Office Resources".to_string(),
                "Location-based Services".to_string(),
            ],
            
            // Default for unrecognized groups - still provide some permissions to enable overlap detection
            _ => vec![
                "Standard User Rights".to_string(),
                format!("Group Membership: {}", group_name),
                "Basic Network Access".to_string(),
            ],
        }
    }

    /// Get description for a permission
    fn get_permission_description(&self, permission: &str) -> String {
        match permission {
            "Full Domain Control" => "Complete administrative control over the entire domain".to_string(),
            "Schema Modification" => "Ability to modify Active Directory schema".to_string(),
            "User Account Management" => "Create, modify, and delete user accounts".to_string(),
            "Group Management" => "Create, modify, and delete security groups".to_string(),
            "Server Management" => "Administrative access to domain servers".to_string(),
            "Backup Operations" => "Ability to backup files and directories".to_string(),
            "Remote Desktop Access" => "Can connect via Remote Desktop Services".to_string(),
            _ => format!("Permission: {}", permission),
        }
    }

    /// Check if permission is critical (highest risk)
    fn is_critical_permission(&self, permission: &str) -> bool {
        matches!(permission, 
            "Full Domain Control" | 
            "Forest-wide Administration" | 
            "Schema Modification"
        )
    }

    /// Check if permission is high risk
    fn is_high_risk_permission(&self, permission: &str) -> bool {
        matches!(permission,
            "Directory Service Access" |
            "Configuration Container Access" |
            "Cross-Domain Access" |
            "User Management"
        )
    }

    /// Check if permission is administrative
    fn is_admin_permission(&self, permission: &str) -> bool {
        permission.contains("Management") || 
        permission.contains("Administration") ||
        permission.contains("Operators")
    }

    /// Check if permission can lead to privilege escalation
    fn is_escalation_permission(&self, permission: &str) -> bool {
        matches!(permission,
            "User Account Management" |
            "Group Management" |
            "Schema Modification" |
            "Directory Service Access"
        )
    }

    /// Check if sources have conflicting permissions
    fn has_conflicting_sources(&self, sources: &[String]) -> bool {
        // Check for conflicting group combinations
        let has_user_operators = sources.iter().any(|s| s.contains("Account Operators"));
        let has_domain_admins = sources.iter().any(|s| s.contains("Domain Admins"));
        
        // Domain Admins with Account Operators is redundant/conflicting
        has_user_operators && has_domain_admins
    }

    /// Check if permission is redundant due to inheritance
    fn is_redundant_permission(&self, _permission: &str, sources: &[String]) -> bool {
        // If Domain Admins is present, most other permissions are redundant
        let has_domain_admins = sources.iter().any(|s| s.contains("Domain Admins"));
        let has_enterprise_admins = sources.iter().any(|s| s.contains("Enterprise Admins"));
        
        (has_domain_admins || has_enterprise_admins) && sources.len() > 1
    }
}