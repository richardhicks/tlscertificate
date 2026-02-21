# Get-TlsCertificate

A PowerShell script for retrieving and examining Transport Layer Security (TLS) certificates from remote servers.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Version](https://img.shields.io/badge/Version-2.4.0-brightgreen.svg)](https://github.com/richardhicks/tlscertificate/blob/main/Get-TlsCertificate.ps1)

## Overview

`Get-TlsCertificate.ps1` is a diagnostic tool for administrators and security professionals to quickly retrieve and inspect TLS certificates from any HTTPS-enabled endpoint. This includes public websites, internal web servers, VPN gateways, LDAPS servers, Remote Desktop Gateway servers, and more.

## Features

- Retrieve TLS certificate details from any HTTPS-enabled server
- Support for custom TCP ports (default: 443)
- Process multiple hostnames in a single command
- Export certificates to PEM format files (saved as `<hostname>.crt` in the current directory)
- Support for both RSA and ECC (Elliptic Curve) certificates
- Detailed certificate information including:
  - Subject and Subject Alternative Names (SANs)
  - Issuer
  - Serial Number and Thumbprint
  - Validity period (Issued/Expires dates)
  - Enhanced Key Usage (EKU)
  - Public key algorithm and key size
  - Signature algorithm

## Requirements

- Windows PowerShell 5.1 or PowerShell 7.x
- .NET Framework 4.5 or later (for Windows PowerShell)
- Network connectivity to target servers

## Installation

### Option 1: PowerShell Gallery (Recommended)

The easiest way to install the script is from the [PowerShell Gallery](https://www.powershellgallery.com/packages/Get-TlsCertificate):

```powershell
# Install for the current user
Install-Script -Name Get-TlsCertificate -Scope CurrentUser
```

```powershell
# Install for all users (requires elevated permissions)
Install-Script -Name Get-TlsCertificate -Scope AllUsers
```

After installation, the script is available from any PowerShell session:

```powershell
Get-TlsCertificate -Hostname 'www.example.com'
```

### Option 2: Download from GitHub

```powershell
# Download the script directly
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/richardhicks/tlscertificate/main/Get-TlsCertificate.ps1" -OutFile "Get-TlsCertificate.ps1"
```

### Option 3: Clone the Repository

```powershell
git clone https://github.com/richardhicks/tlscertificate.git
cd tlscertificate
```

### Option 4: Manual Download

1. Navigate to [https://github.com/richardhicks/tlscertificate](https://github.com/richardhicks/tlscertificate)
2. Click on `Get-TlsCertificate.ps1`
3. Click the **Download** or **Raw** button
4. Save the file to your desired location

## Usage

### Basic Syntax

```powershell
.\Get-TlsCertificate.ps1 -Hostname <String[]> [-Port <Int32>] [-OutFile]
```

### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-Hostname` | Yes | - | The server name or FQDN of the target resource. Accepts multiple values. |
| `-Port` | No | 443 | The TCP port of the target resource. |
| `-OutFile` | No | - | When specified, saves the certificate to the current directory as `<hostname>.crt` in PEM format. |

## Examples

### Web Servers (HTTPS)

**Check a public website certificate:**

```powershell
.\Get-TlsCertificate.ps1 -Hostname 'www.example.com'
```

**Check a website on a non-standard port:**

```powershell
.\Get-TlsCertificate.ps1 -Hostname 'intranet.contoso.com' -Port 8443
```

**Check multiple websites at once:**

```powershell
.\Get-TlsCertificate.ps1 -Hostname 'www.contoso.com', 'www.fabrikam.com', 'www.example.com'
```

### LDAPS Servers (Active Directory)

LDAPS (LDAP over SSL) typically runs on port 636.

**Check an Active Directory domain controller LDAPS certificate:**

```powershell
.\Get-TlsCertificate.ps1 -Hostname 'dc01.contoso.com' -Port 636
```

**Check the Global Catalog LDAPS certificate:**

```powershell
.\Get-TlsCertificate.ps1 -Hostname 'dc01.contoso.com' -Port 3269
```

**Check multiple domain controllers:**

```powershell
$DomainControllers = 'dc01.contoso.com', 'dc02.contoso.com', 'dc03.contoso.com'
.\Get-TlsCertificate.ps1 -Hostname $DomainControllers -Port 636
```

### Remote Desktop Gateway Servers

RD Gateway servers typically use port 443.

**Check an RD Gateway certificate:**

```powershell
.\Get-TlsCertificate.ps1 -Hostname 'rdgw.contoso.com' -Port 443
```

**Check a Remote Desktop Session Host certificate:**

```powershell
.\Get-TlsCertificate.ps1 -Hostname 'rdp01.contoso.com' -Port 3389
```

### VPN Servers

**Check an SSL VPN or SSTP VPN server certificate:**

```powershell
.\Get-TlsCertificate.ps1 -Hostname 'vpn.contoso.com'
```

**Check an Always On VPN server:**

```powershell
.\Get-TlsCertificate.ps1 -Hostname 'aovpn.contoso.com'
```

### ADFS Servers

**Check an AD FS server certificate:**

```powershell
.\Get-TlsCertificate.ps1 -Hostname 'adfs.contoso.com'
```

### Web Application Proxy (WAP)

**Check a Web Application Proxy certificate:**

```powershell
.\Get-TlsCertificate.ps1 -Hostname 'wap.contoso.com'
```

### Database Servers

**Check SQL Server with encrypted connections:**

```powershell
.\Get-TlsCertificate.ps1 -Hostname 'sql.contoso.com' -Port 1433
```

**Check PostgreSQL with SSL:**

```powershell
.\Get-TlsCertificate.ps1 -Hostname 'postgres.contoso.com' -Port 5432
```

### Mail Servers (SMTP/IMAP/POP3 over TLS)

**Check SMTP server with STARTTLS (implicit TLS on port 465):**

```powershell
.\Get-TlsCertificate.ps1 -Hostname 'smtp.contoso.com' -Port 465
```

**Check IMAPS server:**

```powershell
.\Get-TlsCertificate.ps1 -Hostname 'imap.contoso.com' -Port 993
```

**Check POP3S server:**

```powershell
.\Get-TlsCertificate.ps1 -Hostname 'pop.contoso.com' -Port 995
```

### Saving Certificates

**Save a certificate to a file:**

```powershell
.\Get-TlsCertificate.ps1 -Hostname 'www.contoso.com' -OutFile
# Creates: www.contoso.com.crt
```

**Save certificates from multiple hosts (each file is named after its hostname):**

```powershell
.\Get-TlsCertificate.ps1 -Hostname 'www.contoso.com', 'www.fabrikam.com' -OutFile
# Creates: www.contoso.com.crt, www.fabrikam.com.crt
```

### Pipeline Input

**Process hostnames from a file:**

```powershell
Get-Content .\servers.txt | .\Get-TlsCertificate.ps1
```

**Process from an array:**

```powershell
@('www.contoso.com', 'www.fabrikam.com') | .\Get-TlsCertificate.ps1
```

### Verbose Output

**Enable verbose output for troubleshooting:**

```powershell
.\Get-TlsCertificate.ps1 -Hostname 'www.contoso.com' -Verbose
```

## Output

The script returns a custom PowerShell object with the following properties:

| Property | Description |
|----------|-------------|
| `Subject` | The subject name of the certificate |
| `Issuer` | The issuer name of the certificate |
| `SerialNumber` | The serial number of the certificate |
| `Thumbprint` | The SHA-1 thumbprint of the certificate |
| `Issued` | The date and time the certificate is valid from |
| `Expires` | The date and time the certificate expires |
| `AlternativeNames` | The subject alternative names (SANs) of the certificate |
| `EnhancedKeyUsage` | The enhanced key usage (EKU) values of the certificate |
| `PublicKeyAlgorithm` | The public key algorithm (e.g., RSA, ECC) |
| `KeySize` | The size of the public key in bits |
| `SignatureAlgorithm` | The signature algorithm used by the certificate |

### Example Output

```
Subject                 : CN=www.example.com
Issuer                  : CN=DigiCert TLS RSA SHA256 2020 CA1, O=DigiCert Inc, C=US
SerialNumber            : 0123456789ABCDEF0123456789ABCDEF
Thumbprint              : ABCDEF1234567890ABCDEF1234567890ABCDEF12
Issued                  : 1/1/2024 12:00:00 AM
Expires                 : 1/1/2025 11:59:59 PM
AlternativeNames        : {www.example.com, example.com}
EnhancedKeyUsage        : {Server Authentication}
PublicKeyAlgorithm      : RSA
KeySize                 : 2048
SignatureAlgorithm      : sha256RSA
```

## Common Use Cases

### Certificate Expiration Monitoring

```powershell
# Check if a certificate expires within 30 days
$cert = .\Get-TlsCertificate.ps1 -Hostname 'www.contoso.com'
$daysUntilExpiry = ($cert.Expires - (Get-Date)).Days

if ($daysUntilExpiry -lt 30) {
    Write-Warning "Certificate expires in $daysUntilExpiry days!"
}
```

### Bulk Certificate Audit

```powershell
# Audit certificates across multiple servers
$servers = @(
    'www.contoso.com',
    'mail.contoso.com',
    'vpn.contoso.com',
    'adfs.contoso.com'
)

$results = $servers | ForEach-Object {
    .\Get-TlsCertificate.ps1 -Hostname $_ | 
    Select-Object @{N='Hostname';E={$_}}, Subject, Expires, Thumbprint
}

$results | Format-Table -AutoSize
```

### Export to CSV

```powershell
.\Get-TlsCertificate.ps1 -Hostname 'www.contoso.com', 'mail.contoso.com' | 
    Export-Csv -Path '.\certificates.csv' -NoTypeInformation
```

## Troubleshooting

### Connection Failures

If you receive "Failed to connect" errors:

1. Verify network connectivity to the target server
2. Ensure the correct port is specified
3. Check firewall rules between your machine and the target
4. Verify the service is running on the target server

### Certificate Validation Errors

The script intentionally ignores certificate validation errors to allow inspection of certificates that may have issues (expired, self-signed, wrong hostname, etc.). Validation errors are displayed when using the `-Verbose` parameter.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Richard M. Hicks**

- Website: [https://www.richardhicks.com/](https://www.richardhicks.com/)
- GitHub: [https://github.com/richardhicks/](https://github.com/richardhicks/)
- X: [@richardhicks](https://x.com/richardhicks)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Support

If you encounter any issues or have questions, please [open an issue](https://github.com/richardhicks/tlscertificate/issues) on GitHub.
