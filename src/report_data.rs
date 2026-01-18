use chrono::{DateTime, Utc};
use crate::models::{ADUser, ReportData};
use crate::risk_calculator::RiskAssessment;

#[derive(Debug, Clone)]
pub struct EnhancedReportData {
    pub basic_report: ReportData,
    pub risk_assessment: Option<RiskAssessment>,
}

impl EnhancedReportData {
    pub fn new(
        user: ADUser,
        domain_name: String,
        domain_controller: String,
        risk_assessment: Option<RiskAssessment>,
    ) -> Self {
        let basic_report = ReportData {
            user,
            generation_time: Utc::now(),
            domain_name,
            domain_controller,
        };

        Self {
            basic_report,
            risk_assessment,
        }
    }

    pub fn user(&self) -> &ADUser {
        &self.basic_report.user
    }

    pub fn generation_time(&self) -> DateTime<Utc> {
        self.basic_report.generation_time
    }

    pub fn domain_name(&self) -> &str {
        &self.basic_report.domain_name
    }

    pub fn domain_controller(&self) -> &str {
        &self.basic_report.domain_controller
    }
}