# Active Directory Report Generator

An internal tool for generating comprehensive PDF reports for Active Directory users, including permission analysis, group memberships, and security risk assessments.

## Features

- **Automated AD Integration**: Connects to Active Directory using LDAP with support for Windows authentication (Kerberos/GSSAPI)
- **Comprehensive User Analysis**: 
  - User account details and attributes
  - Group memberships (direct and nested)
  - Permission analysis
  - Security risk scoring
- **Flexible Authentication**:
  - Windows integrated authentication (auto-detects domain controller)
  - Username/password authentication
  - Cross-platform support
- **Batch Processing**: Generate reports for multiple users from a list
- **PDF Output**: Professional PDF reports with detailed user information
- **Diagnostics Mode**: Built-in troubleshooting capabilities for connection and authentication issues

## Installation

### Prerequisites

- Rust 1.70 or higher
- Windows domain environment (for Windows authentication)
- Network access to domain controllers

### Building from Source

```bash
# Clone the repository
git clone <repository-url>
cd ActiveDirectory

# Build the project
cargo build --release

# The binary will be available at target/release/ad-report
```

## Usage

### Basic Usage

Generate a report for a single user:
```bash
ad-report --target-user john.doe
```

### Authentication Options

#### Windows Integrated Authentication (Windows only)
```bash
# Auto-detects domain controller and uses current Windows credentials
ad-report --target-user john.doe
```

#### Username/Password Authentication
```bash
# Specify server and credentials
ad-report --server dc.domain.com --username "DOMAIN\\admin" --target-user john.doe

# Password will be prompted if not provided
ad-report --server dc.domain.com --username admin@domain.com --target-user john.doe
```

### Batch Processing

Process multiple users from a file:
```bash
ad-report --user-list users.txt
```

The user list file should contain one username per line.

### Advanced Options

```bash
# Specify base DN for LDAP queries
ad-report --base-dn "DC=company,DC=local" --target-user john.doe

# Set custom output directory
ad-report --output-dir ./reports --target-user john.doe

# Enable verbose logging
ad-report --verbose --target-user john.doe

# Run diagnostics
ad-report --diagnostics

# Batch processing with risk analysis and GSSAPI authentication
ad-report --server dc.example.com --user-list users.txt --risk-analysis --use-gssapi
```

## Command Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--server` | `-s` | LDAP/AD server hostname or IP address (auto-detected on Windows) |
| `--username` | `-u` | Username for LDAP authentication |
| `--password` | `-p` | Password for LDAP authentication (prompted if not provided) |
| `--target-user` | `-t` | Target user to generate report for |
| `--user-list` | `-l` | File containing list of users to process |
| `--base-dn` | `-b` | Base Distinguished Name for LDAP queries |
| `--output-dir` | `-o` | Output directory for PDF reports (default: current directory) |
| `--verbose` | `-v` | Enable verbose logging |
| `--diagnostics` | | Run diagnostics mode for troubleshooting |
| `--risk-analysis` | | Include detailed risk assessment in report |
| `--use-gssapi` | | Use Kerberos/GSSAPI authentication (Windows integrated, no password required) |

## Output

Reports are generated as PDF files in the format:
```
AD_Report_<username>_<timestamp>.pdf
```

Each report includes:
- User account information
- Group memberships with descriptions
- Permission analysis
- Security risk score and assessment
- Last logon information
- Account status and flags

## Security Considerations

- Credentials are never stored in plaintext
- Windows authentication uses Kerberos when available
- All LDAP connections use secure bindings
- Sensitive information in reports should be handled according to organizational policies

## Troubleshooting

### Connection Issues

Run diagnostics mode to test connectivity:
```bash
ad-report --diagnostics
```

### Authentication Failures

- Ensure correct username format (DOMAIN\\username or UPN)
- Verify account has necessary permissions to read AD
- Check network connectivity to domain controller

### Common Issues

1. **"Cannot find domain controller"**: Ensure the system is domain-joined or specify server manually
2. **"Authentication failed"**: Verify credentials and account permissions
3. **"User not found"**: Check the username spelling and that the user exists in AD

## Development

### Project Structure

```
src/
├── main.rs              # CLI entry point and orchestration
├── ldap_client.rs       # LDAP connection and queries
├── windows_auth.rs      # Windows authentication handling
├── models.rs            # Data structures
├── permission_analyzer.rs # Permission analysis logic
├── risk_calculator.rs   # Security risk scoring
├── pdf_generator.rs     # PDF report generation
├── report_data.rs       # Report data preparation
└── diagnostics.rs       # Diagnostic utilities
```

### Building for Different Platforms

```bash
# Windows with GSSAPI support
cargo build --release --target x86_64-pc-windows-msvc

# Linux/macOS (without GSSAPI)
cargo build --release
```