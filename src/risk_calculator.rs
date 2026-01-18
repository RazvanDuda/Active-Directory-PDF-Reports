use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};
use crate::models::{ADUser, ADGroup, UserRight, RightSource};
use crate::permission_analyzer::{PermissionAnalyzer, OverlapAnalysis, RiskLevel};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub overall_score: u8,                    // 0-100 risk score
    pub risk_level: RiskLevel,
    pub contributing_factors: Vec<RiskFactor>,
    pub recommendations: Vec<String>,
    pub risk_breakdown: RiskBreakdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub factor_type: RiskFactorType,
    pub description: String,
    pub risk_contribution: u8,                // 0-100
    pub severity: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskFactorType {
    AdministrativeAccess,
    PrivilegedGroups,
    ServiceAccount,
    DormantAccount,
    PermissionOverlap,
    ExcessivePrivileges,
    WeakAccountSecurity,
    CrossDomainAccess,
    DataAccess,
    PrivilegeEscalation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskBreakdown {
    pub administrative_risk: u8,              // Risk from admin groups
    pub permission_overlap_risk: u8,          // Risk from overlapping permissions
    pub account_security_risk: u8,            // Risk from account configuration
    pub activity_risk: u8,                    // Risk from account activity patterns
}

pub struct RiskCalculator {
    permission_analyzer: PermissionAnalyzer,
}

impl RiskCalculator {
    pub fn new() -> Self {
        Self {
            permission_analyzer: PermissionAnalyzer::new(),
        }
    }

    /// Calculate comprehensive risk assessment for a user
    pub fn calculate_risk(&self, user: &ADUser) -> RiskAssessment {
        let mut risk_factors = Vec::new();
        let mut total_risk_score = 0u8;

        // Analyze permission overlaps
        let overlap_analysis = self.permission_analyzer.analyze_overlaps(user);
        
        // Calculate individual risk components
        let admin_risk = self.calculate_administrative_risk(user, &mut risk_factors);
        let overlap_risk = self.calculate_overlap_risk(&overlap_analysis, &mut risk_factors);
        let security_risk = self.calculate_account_security_risk(user, &mut risk_factors);
        let activity_risk = self.calculate_activity_risk(user, &mut risk_factors);

        // Combine risk scores with weights
        total_risk_score = self.combine_risk_scores(admin_risk, overlap_risk, security_risk, activity_risk);

        let risk_level = self.determine_risk_level(total_risk_score);
        let recommendations = self.generate_recommendations(user, &risk_factors, &overlap_analysis);

        let risk_breakdown = RiskBreakdown {
            administrative_risk: admin_risk,
            permission_overlap_risk: overlap_risk,
            account_security_risk: security_risk,
            activity_risk,
        };

        RiskAssessment {
            overall_score: total_risk_score,
            risk_level,
            contributing_factors: risk_factors,
            recommendations,
            risk_breakdown,
        }
    }

    /// Calculate risk from administrative group memberships
    fn calculate_administrative_risk(&self, user: &ADUser, risk_factors: &mut Vec<RiskFactor>) -> u8 {
        let mut admin_risk = 0u8;

        for group in user.all_groups() {
            let (risk_contribution, severity) = match group.name.as_str() {
                name if name.contains("Domain Admins") => {
                    risk_factors.push(RiskFactor {
                        factor_type: RiskFactorType::AdministrativeAccess,
                        description: "Member of Domain Admins group - full domain control".to_string(),
                        risk_contribution: 90,
                        severity: RiskLevel::Critical,
                    });
                    (90, RiskLevel::Critical)
                },
                name if name.contains("Enterprise Admins") => {
                    risk_factors.push(RiskFactor {
                        factor_type: RiskFactorType::AdministrativeAccess,
                        description: "Member of Enterprise Admins group - forest-wide control".to_string(),
                        risk_contribution: 95,
                        severity: RiskLevel::Critical,
                    });
                    (95, RiskLevel::Critical)
                },
                name if name.contains("Schema Admins") => {
                    risk_factors.push(RiskFactor {
                        factor_type: RiskFactorType::AdministrativeAccess,
                        description: "Member of Schema Admins group - can modify AD schema".to_string(),
                        risk_contribution: 80,
                        severity: RiskLevel::Critical,
                    });
                    (80, RiskLevel::Critical)
                },
                name if name.contains("Account Operators") => {
                    risk_factors.push(RiskFactor {
                        factor_type: RiskFactorType::PrivilegedGroups,
                        description: "Member of Account Operators - can manage user accounts".to_string(),
                        risk_contribution: 60,
                        severity: RiskLevel::High,
                    });
                    (60, RiskLevel::High)
                },
                name if name.contains("Server Operators") => {
                    risk_factors.push(RiskFactor {
                        factor_type: RiskFactorType::PrivilegedGroups,
                        description: "Member of Server Operators - can manage domain servers".to_string(),
                        risk_contribution: 65,
                        severity: RiskLevel::High,
                    });
                    (65, RiskLevel::High)
                },
                name if name.contains("Backup Operators") => {
                    risk_factors.push(RiskFactor {
                        factor_type: RiskFactorType::PrivilegedGroups,
                        description: "Member of Backup Operators - backup/restore privileges".to_string(),
                        risk_contribution: 45,
                        severity: RiskLevel::Medium,
                    });
                    (45, RiskLevel::Medium)
                },
                
                // Enhanced risk assessment for custom business groups
                name if group.name.to_lowercase().contains("breakglass") || group.name.to_lowercase().contains("emergency") => {
                    risk_factors.push(RiskFactor {
                        factor_type: RiskFactorType::AdministrativeAccess,
                        description: format!("Emergency access group '{}' - critical system access", group.name),
                        risk_contribution: 70,
                        severity: RiskLevel::High,
                    });
                    (70, RiskLevel::High)
                },
                
                name if group.name.to_lowercase().contains("admin") || group.name.to_lowercase().contains("administrator") => {
                    let risk = if group.name.to_lowercase().contains("database") || group.name.to_lowercase().contains("db") { 50 } else { 40 };
                    risk_factors.push(RiskFactor {
                        factor_type: RiskFactorType::AdministrativeAccess,
                        description: format!("Administrative group '{}' - elevated privileges", group.name),
                        risk_contribution: risk,
                        severity: if risk >= 50 { RiskLevel::High } else { RiskLevel::Medium },
                    });
                    (risk, if risk >= 50 { RiskLevel::High } else { RiskLevel::Medium })
                },
                
                name if group.name.to_lowercase().contains("developer") || group.name.to_lowercase().contains("dev") => {
                    let risk = if group.name.to_lowercase().contains("prod") { 45 } else { 25 };
                    risk_factors.push(RiskFactor {
                        factor_type: RiskFactorType::DataAccess,
                        description: format!("Developer group '{}' - code/system access", group.name),
                        risk_contribution: risk,
                        severity: if risk >= 40 { RiskLevel::Medium } else { RiskLevel::Low },
                    });
                    (risk, if risk >= 40 { RiskLevel::Medium } else { RiskLevel::Low })
                },
                
                name if group.name.to_lowercase().contains("database") || group.name.to_lowercase().contains("db") => {
                    let risk = if group.name.to_lowercase().contains("rw") || group.name.to_lowercase().contains("write") { 35 } else { 20 };
                    if risk >= 30 {
                        risk_factors.push(RiskFactor {
                            factor_type: RiskFactorType::DataAccess,
                            description: format!("Database access group '{}' - sensitive data access", group.name),
                            risk_contribution: risk,
                            severity: RiskLevel::Medium,
                        });
                    }
                    (risk, if risk >= 30 { RiskLevel::Medium } else { RiskLevel::Low })
                },
                
                name if group.name.to_lowercase().contains("it") && (group.name.to_lowercase().contains("user") || group.name.to_lowercase().contains("staff")) => {
                    risk_factors.push(RiskFactor {
                        factor_type: RiskFactorType::AdministrativeAccess,
                        description: format!("IT administrative group '{}' - technical privileges", group.name),
                        risk_contribution: 30,
                        severity: RiskLevel::Medium,
                    });
                    (30, RiskLevel::Medium)
                },
                
                _ => (5, RiskLevel::Low), // Default minor risk for any group membership
            };

            admin_risk = admin_risk.saturating_add(risk_contribution);
        }
        
        // Add risk factor for excessive group memberships
        let total_groups = user.groups.len() + if user.primary_group.is_some() { 1 } else { 0 };
        if total_groups > 15 {
            risk_factors.push(RiskFactor {
                factor_type: RiskFactorType::PrivilegeEscalation,
                description: format!("Excessive group memberships ({} groups) - access accumulation risk", total_groups),
                risk_contribution: ((total_groups - 15) as u8).min(25),
                severity: if total_groups > 25 { RiskLevel::High } else { RiskLevel::Medium },
            });
            admin_risk = admin_risk.saturating_add(((total_groups - 15) as u8).min(25));
        }

        // Cap at 100
        admin_risk.min(100)
    }

    /// Calculate risk from permission overlaps
    fn calculate_overlap_risk(&self, overlap_analysis: &OverlapAnalysis, risk_factors: &mut Vec<RiskFactor>) -> u8 {
        let mut overlap_risk = 0u8;

        // Risk from redundancy score
        let redundancy_risk = (overlap_analysis.redundancy_score / 2.0) as u8;
        overlap_risk = overlap_risk.saturating_add(redundancy_risk);

        // Risk from critical overlaps
        if overlap_analysis.risk_summary.critical_overlaps > 0 {
            let critical_risk = (overlap_analysis.risk_summary.critical_overlaps * 25).min(75) as u8;
            overlap_risk = overlap_risk.saturating_add(critical_risk);
            
            risk_factors.push(RiskFactor {
                factor_type: RiskFactorType::PermissionOverlap,
                description: format!("{} critical permission overlaps detected", 
                    overlap_analysis.risk_summary.critical_overlaps),
                risk_contribution: critical_risk,
                severity: RiskLevel::Critical,
            });
        }

        // Risk from high overlaps
        if overlap_analysis.risk_summary.high_overlaps > 0 {
            let high_risk = (overlap_analysis.risk_summary.high_overlaps * 15).min(50) as u8;
            overlap_risk = overlap_risk.saturating_add(high_risk);
            
            risk_factors.push(RiskFactor {
                factor_type: RiskFactorType::PermissionOverlap,
                description: format!("{} high-risk permission overlaps detected", 
                    overlap_analysis.risk_summary.high_overlaps),
                risk_contribution: high_risk,
                severity: RiskLevel::High,
            });
        }

        // High redundancy risk
        if overlap_analysis.redundancy_score > 50.0 {
            risk_factors.push(RiskFactor {
                factor_type: RiskFactorType::ExcessivePrivileges,
                description: format!("High permission redundancy: {:.1}%", overlap_analysis.redundancy_score),
                risk_contribution: redundancy_risk,
                severity: RiskLevel::Medium,
            });
        }

        overlap_risk.min(100)
    }

    /// Calculate risk from account security configuration
    fn calculate_account_security_risk(&self, user: &ADUser, risk_factors: &mut Vec<RiskFactor>) -> u8 {
        let mut security_risk = 0u8;

        // Password never expires
        if user.password_never_expires {
            security_risk = security_risk.saturating_add(30);
            risk_factors.push(RiskFactor {
                factor_type: RiskFactorType::WeakAccountSecurity,
                description: "Password set to never expire".to_string(),
                risk_contribution: 30,
                severity: RiskLevel::Medium,
            });
        }

        // Account disabled but with high privileges
        if !user.account_enabled && !user.all_groups().is_empty() {
            let disabled_risk = if user.all_groups().iter().any(|g| g.name.contains("Admin")) { 40 } else { 20 };
            security_risk = security_risk.saturating_add(disabled_risk);
            risk_factors.push(RiskFactor {
                factor_type: RiskFactorType::DormantAccount,
                description: "Disabled account with retained privileges".to_string(),
                risk_contribution: disabled_risk,
                severity: if disabled_risk > 30 { RiskLevel::High } else { RiskLevel::Medium },
            });
        }

        // Account locked
        if user.account_locked {
            security_risk = security_risk.saturating_add(15);
            risk_factors.push(RiskFactor {
                factor_type: RiskFactorType::WeakAccountSecurity,
                description: "Account is currently locked".to_string(),
                risk_contribution: 15,
                severity: RiskLevel::Low,
            });
        }

        // Service account indicators
        if self.is_service_account(user) {
            security_risk = security_risk.saturating_add(25);
            risk_factors.push(RiskFactor {
                factor_type: RiskFactorType::ServiceAccount,
                description: "Account appears to be a service account".to_string(),
                risk_contribution: 25,
                severity: RiskLevel::Medium,
            });
        }

        security_risk.min(100)
    }

    /// Calculate risk from account activity patterns
    fn calculate_activity_risk(&self, user: &ADUser, risk_factors: &mut Vec<RiskFactor>) -> u8 {
        let mut activity_risk = 0u8;
        let now = Utc::now();

        // Check last logon time
        if let Some(last_logon) = user.last_logon {
            let days_since_logon = (now - last_logon).num_days();
            
            if days_since_logon > 90 && !user.all_groups().is_empty() {
                let dormant_risk = if days_since_logon > 365 { 50 } else { 30 };
                activity_risk = activity_risk.saturating_add(dormant_risk);
                
                risk_factors.push(RiskFactor {
                    factor_type: RiskFactorType::DormantAccount,
                    description: format!("Account inactive for {} days with retained privileges", days_since_logon),
                    risk_contribution: dormant_risk,
                    severity: if dormant_risk > 40 { RiskLevel::High } else { RiskLevel::Medium },
                });
            }
        } else {
            // Never logged on but has privileges
            if !user.all_groups().is_empty() {
                activity_risk = activity_risk.saturating_add(40);
                risk_factors.push(RiskFactor {
                    factor_type: RiskFactorType::DormantAccount,
                    description: "Account has never logged on but has privileges".to_string(),
                    risk_contribution: 40,
                    severity: RiskLevel::High,
                });
            }
        }

        activity_risk.min(100)
    }

    /// Combine risk scores with appropriate weights
    fn combine_risk_scores(&self, admin_risk: u8, overlap_risk: u8, security_risk: u8, activity_risk: u8) -> u8 {
        // Weighted combination: admin risk has highest weight
        let weighted_score = (admin_risk as f32 * 0.4) +
                            (overlap_risk as f32 * 0.25) +
                            (security_risk as f32 * 0.20) +
                            (activity_risk as f32 * 0.15);
        
        weighted_score.round() as u8
    }

    /// Determine overall risk level from score
    fn determine_risk_level(&self, score: u8) -> RiskLevel {
        match score {
            80..=100 => RiskLevel::Critical,
            60..=79 => RiskLevel::High,
            30..=59 => RiskLevel::Medium,
            _ => RiskLevel::Low,
        }
    }

    /// Generate recommendations based on risk factors
    fn generate_recommendations(&self, user: &ADUser, risk_factors: &[RiskFactor], overlap_analysis: &OverlapAnalysis) -> Vec<String> {
        let mut recommendations = Vec::new();

        // Administrative access recommendations
        if risk_factors.iter().any(|rf| matches!(rf.factor_type, RiskFactorType::AdministrativeAccess)) {
            recommendations.push("Review necessity of administrative group memberships".to_string());
            recommendations.push("Consider using Privileged Access Management (PAM) solutions".to_string());
            recommendations.push("Implement just-in-time access for administrative tasks".to_string());
        }

        // Permission overlap recommendations
        if overlap_analysis.redundancy_score > 30.0 {
            recommendations.push("Remove redundant group memberships".to_string());
            recommendations.push("Implement principle of least privilege".to_string());
        }

        // Account security recommendations
        if user.password_never_expires {
            recommendations.push("Enable password expiration policy".to_string());
        }

        // Dormant account recommendations
        if risk_factors.iter().any(|rf| matches!(rf.factor_type, RiskFactorType::DormantAccount)) {
            recommendations.push("Disable or remove unused accounts".to_string());
            recommendations.push("Implement regular account review processes".to_string());
        }

        // Service account recommendations
        if risk_factors.iter().any(|rf| matches!(rf.factor_type, RiskFactorType::ServiceAccount)) {
            recommendations.push("Use Managed Service Accounts where possible".to_string());
            recommendations.push("Review service account permissions regularly".to_string());
        }

        // General recommendations
        recommendations.push("Implement regular access reviews".to_string());
        recommendations.push("Monitor account activity for anomalies".to_string());
        
        recommendations
    }

    /// Check if account appears to be a service account
    fn is_service_account(&self, user: &ADUser) -> bool {
        // Service account indicators
        let name_indicators = user.sam_account_name.to_lowercase();
        let service_patterns = ["svc", "service", "sql", "iis", "app", "system"];
        
        service_patterns.iter().any(|pattern| name_indicators.contains(pattern)) ||
        user.password_never_expires && user.last_logon.is_none()
    }
}