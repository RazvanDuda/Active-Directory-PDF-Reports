use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::Parser;
use rpassword::prompt_password;
use regex::Regex;
use std::fs::File;
use std::io::{Write, BufRead, BufReader};
use tracing::{info, debug, warn, error};
use tracing_subscriber;

mod models;
mod ldap_client;
mod pdf_generator;
mod windows_auth;
mod permission_analyzer;
mod risk_calculator;
mod report_data;
mod diagnostics;

use ldap_client::LdapClient;
use pdf_generator::PdfGenerator;
use windows_auth::{WindowsAuth, should_use_gssapi, get_default_ldap_server};
use risk_calculator::RiskCalculator;
use report_data::EnhancedReportData;
use diagnostics::Diagnostics;

#[derive(Parser, Debug)]
#[clap(
    name = "ad-report",
    version = "0.1.0",
    about = "Generate PDF reports for Active Directory users",
    long_about = None
)]
struct Args {
    /// LDAP/AD server hostname or IP address (auto-detected on Windows if not provided)
    #[arg(short = 's', long)]
    server: Option<String>,

    /// Username for LDAP authentication (e.g., "DOMAIN\\username" or "username@domain.com")
    /// Optional when using Windows authentication
    #[arg(short = 'u', long)]
    username: Option<String>,

    /// Password for LDAP authentication (will prompt if not provided)
    #[arg(short = 'p', long, hide = true)]
    password: Option<String>,

    /// Target user to generate report for (SAM account name)
    #[arg(short = 't', long, conflicts_with = "user_list")]
    target_user: Option<String>,

    /// Path to text file containing list of users (one username per line)
    #[arg(short = 'l', long, conflicts_with = "target_user")]
    user_list: Option<String>,

    /// Output PDF file path (optional - will auto-generate if not provided)
    #[arg(short = 'o', long)]
    output: Option<String>,

    /// Domain name
    #[arg(short = 'd', long)]
    domain: Option<String>,

    /// Use TLS for LDAP connection
    #[arg(long, default_value = "true")]
    use_tls: bool,

    /// Use Kerberos/GSSAPI authentication (Windows integrated, no password required)
    /// Only works on domain-joined Windows machines
    #[arg(long)]
    use_gssapi: bool,

    /// Run diagnostics for GSSAPI authentication and exit
    /// Shows preflight checks and troubleshooting guide
    #[arg(long)]
    diagnose: bool,

    /// Include detailed risk assessment in report
    #[arg(long)]
    risk_analysis: bool,

    /// Enable verbose logging
    #[arg(short = 'v', long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    
    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .init();

    info!("Starting Active Directory user report generation");

    // Handle diagnostics request
    if args.diagnose {
        info!("Running GSSAPI diagnostics...\n");

        // Get server for diagnostics
        let server = args.server.clone().unwrap_or_else(|| {
            get_default_ldap_server().unwrap_or_else(|| {
                "ad.example.com".to_string()
            })
        });

        Diagnostics::run_preflight_checks(&server)?;
        Diagnostics::show_troubleshooting_guide();
        Diagnostics::show_auth_info();
        return Ok(());
    }

    // Validate that target user(s) are provided
    if args.target_user.is_none() && args.user_list.is_none() {
        return Err(anyhow::anyhow!("Either --target-user or --user-list must be provided"));
    }

    // Determine server and authentication method
    let server = args.server.clone().unwrap_or_else(|| {
        get_default_ldap_server().unwrap_or_else(|| {
            panic!("LDAP server must be provided when not on a Windows domain")
        })
    });

    info!("Server: {}", server);

    // Determine authentication method
    let use_gssapi_flag = should_use_gssapi(&args.username, args.use_gssapi);

    if use_gssapi_flag {
        // GSSAPI/Kerberos authentication (Windows integrated)
        info!("GSSAPI authentication requested");

        // Validate server FQDN for GSSAPI
        let server_fqdn = WindowsAuth::validate_server_dns(&server)
            .context("Invalid server FQDN for GSSAPI authentication")?;

        // Get current user info
        let (domain, username) = WindowsAuth::get_current_user()
            .context("Failed to get current user information")?;

        info!("Current user: {}\\{}", domain, username);
        info!("Authenticating using Kerberos/GSSAPI...");

        debug!("Connecting to LDAP server...");
        let mut client = LdapClient::connect(&server, args.use_tls)
            .await
            .context("Failed to connect to LDAP server")?;

        info!("Connected to LDAP server");

        debug!("Attempting GSSAPI bind to: {}", server_fqdn);
        client.bind_gssapi(&server_fqdn)
            .await
            .context("GSSAPI authentication failed. Run with --diagnose for troubleshooting help")?;

        info!("Successfully authenticated with Kerberos/GSSAPI");

        // Extract domain for reporting
        let report_domain = args.domain.clone().unwrap_or_else(|| domain);

        // Continue with user processing using authenticated client
        process_users(&mut client, &server, &report_domain, &args).await?;
    } else {
        // Simple authentication (username/password)
        let (username, password) = if let Some(u) = args.username.clone() {
            // Username provided
            let pwd = match args.password.clone() {
                Some(p) => p,
                None => {
                    prompt_password(&format!("Enter password for {}: ", u))
                        .context("Failed to read password")?
                }
            };
            (u, pwd)
        } else {
            panic!("Either --use-gssapi or --username must be provided")
        };

        // Extract domain from username or use provided domain
        let domain = args.domain.clone().unwrap_or_else(|| {
            if username.contains('\\') {
                username.split('\\').next().unwrap_or("").to_string()
            } else if username.contains('@') {
                username.split('@').last().unwrap_or(&server).to_string()
            } else {
                WindowsAuth::get_current_domain().unwrap_or_else(|| server.clone())
            }
        });

        debug!("Connecting to LDAP server...");
        let mut client = LdapClient::connect(&server, args.use_tls)
            .await
            .context("Failed to connect to LDAP server")?;

        info!("Connected to LDAP server");

        debug!("Authenticating with simple bind...");
        client.bind_simple(&username, &password)
            .await
            .context("Failed to authenticate with LDAP")?;

        info!("Successfully authenticated");

        // Continue with user processing using authenticated client
        process_users(&mut client, &server, &domain, &args).await?;
    }

    Ok(())
}

/// Process all target users and generate reports
async fn process_users(
    client: &mut LdapClient,
    server: &str,
    domain: &str,
    args: &Args,
) -> Result<()> {
    // Determine target users
    let target_users = if let Some(user_list_file) = &args.user_list {
        info!("Loading user list from: {}", user_list_file);
        let users = read_user_list(user_list_file)
            .context("Failed to read user list file")?;
        info!("Loaded {} users from file", users.len());
        users
    } else if let Some(target_user) = &args.target_user {
        vec![target_user.clone()]
    } else {
        return Err(anyhow::anyhow!("Either --target-user or --user-list must be provided"));
    };

    // Track success and failure counts
    let mut successful = 0;
    let mut failed = 0;
    let mut generated_files = Vec::new();

    // Check if custom output path is specified (only valid for single user)
    if args.output.is_some() && target_users.len() > 1 {
        warn!("Custom output path (-o) is ignored when processing multiple users");
    }

    // Process each target user
    for (index, target_user) in target_users.iter().enumerate() {
        info!("[{}/{}] Processing user: {}", index + 1, target_users.len(), target_user);

        let custom_output = if target_users.len() == 1 {
            args.output.as_ref().map(|s| s.as_str())
        } else {
            None
        };

        match process_user(
            client,
            target_user,
            &domain,
            &server,
            &args,
            custom_output,
        ).await {
            Ok(output_path) => {
                successful += 1;
                generated_files.push(output_path.clone());
                info!("[{}/{}] ✓ Report saved: {}", index + 1, target_users.len(), output_path);
            }
            Err(e) => {
                failed += 1;
                error!("[{}/{}] ✗ Failed to process {}: {}", index + 1, target_users.len(), target_user, e);
            }
        }
    }

    // Summary
    info!("");
    info!("=== Report Generation Summary ===");
    info!("Total users processed: {}", target_users.len());
    info!("Successful: {}", successful);
    info!("Failed: {}", failed);

    if !generated_files.is_empty() {
        info!("");
        info!("Generated reports:");
        for file in generated_files {
            info!("  - {}", file);
        }
    }

    if failed > 0 {
        warn!("Some reports failed to generate. Check the logs above for details.");
    }

    Ok(())
}

/// Process a single user and generate their report
async fn process_user(
    client: &mut LdapClient,
    target_user: &str,
    domain: &str,
    server: &str,
    args: &Args,
    custom_output: Option<&str>,
) -> Result<String> {
    // Get user information
    debug!("Retrieving user information for: {}", target_user);
    let user = client.get_user(target_user)
        .await
        .context(format!("Failed to retrieve user information for {}", target_user))?;

    debug!("User {} has {} direct group memberships", target_user, user.groups.len());
    debug!("User {} has {} rights/privileges", target_user, user.user_rights.len());

    // Perform risk assessment
    let risk_assessment = if args.risk_analysis {
        debug!("Calculating risk assessment for {}...", target_user);
        let risk_calculator = RiskCalculator::new();
        Some(risk_calculator.calculate_risk(&user))
    } else {
        None
    };

    // Log analysis results
    if let Some(ref risk) = risk_assessment {
        debug!("Risk assessment for {}: Overall score {}/100 ({:?})",
            target_user, risk.overall_score, risk.risk_level);
    }

    // Create enhanced report data
    let report_data = EnhancedReportData::new(
        user,
        domain.to_string(),
        server.to_string(),
        risk_assessment,
    );

    // Generate PDF
    debug!("Generating PDF report for {}...", target_user);
    let mut pdf_gen = PdfGenerator::new()
        .context("Failed to initialize PDF generator")?;

    let pdf_bytes = pdf_gen.generate_report(&report_data)
        .context("Failed to generate PDF report")?;

    // Generate output filename
    let output_path = match custom_output {
        Some(path) => path.to_string(),
        None => generate_filename(target_user, &report_data.generation_time()),
    };

    // Save PDF to file
    let mut file = File::create(&output_path)
        .context("Failed to create output file")?;

    file.write_all(&pdf_bytes)
        .context("Failed to write PDF to file")?;

    Ok(output_path)
}

/// Generate a sanitized filename for the PDF report based on the target user
fn generate_filename(target_user: &str, timestamp: &DateTime<Utc>) -> String {
    // Sanitize username for filesystem compatibility
    let re = Regex::new(r#"[<>:"/\\|?*]"#).unwrap();
    let clean_username = re.replace_all(target_user, "_").to_string();

    // Generate timestamp string
    let time_str = timestamp.format("%Y%m%d_%H%M%S");

    // Create filename
    format!("{}_ad_report_{}.pdf", clean_username, time_str)
}

/// Read list of usernames from a text file (one per line)
fn read_user_list(file_path: &str) -> Result<Vec<String>> {
    let file = File::open(file_path)
        .context(format!("Failed to open user list file: {}", file_path))?;

    let reader = BufReader::new(file);
    let mut users = Vec::new();

    for (line_num, line) in reader.lines().enumerate() {
        let line = line.context(format!("Failed to read line {} from file", line_num + 1))?;
        let username = line.trim().to_string();

        // Skip empty lines and comments
        if !username.is_empty() && !username.starts_with('#') {
            users.push(username);
        }
    }

    Ok(users)
}
