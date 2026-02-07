<#PSScriptInfo

.VERSION 1.0

.GUID 02769b70-101d-404f-bfa1-c76117641280

.AUTHOR Richard Hicks

.COMPANYNAME Richard M. Hicks Consulting, Inc.

.COPYRIGHT Copyright (C) 2026 Richard M. Hicks Consulting, Inc. All Rights Reserved.

.LICENSE Licensed under the MIT License. See LICENSE file in the project root for full license information.

.LICENSEURI https://github.com/richardhicks/tlscertificate/blob/main/LICENSE

.PROJECTURI https://github.com/richardhicks/tlscertificate

.TAGS SSL, TLS, certificate, X509

#>

<#

.SYNOPSIS
    View and optionally save to a file the Transport Layer Security (TLS) certificate for a website or service using HTTPS.

.PARAMETER Hostname
    The server name or Fully Qualified Domain Name (FQDN) of the target resource.

.PARAMETER Port
    The TCP port of the target resource. The default is 443.

.PARAMETER OutFile
    When this parameter is added the TLS certificate will be saved as a file in this location.

.EXAMPLE
    .\Get-TlsCertificate -Hostname 'www.richardhicks.com'

    Displays the TLS certificate for the website https://www.richardhicks.com/.

.EXAMPLE
    .\Get-TlsCertificate -Hostname 'www.richardhicks.com' -Port 8443

    Displays the TLS certificate for the website https://www.richardhicks.com/ listening on the nonstandard port 8443.

.EXAMPLE
    .\Get-TlsCertificate -Hostname 'www.richardhicks.com, www.richardhicks.net'

    Displays the TLS certificates for the websites https://www.richardhicks.com/ and https://www.richardhicks.net/.

.EXAMPLE
    .\Get-TlsCertificate -Hostname 'www.richardhicks.com' -OutFile .\tlscert.crt

    Displays the TLS certificate for the website https://www.richardhicks.com/ and saves the certificate to a file named .\tlscert.crt.

.DESCRIPTION
    This PowerShell script is helpful for troubleshooting TLS issues associated with public websites or other HTTPS services like TLS VPNs. Using this script, administrators can view and optionally save the certificate returned during the TLS handshake. Administrators can confirm certificate details and perform revocation checks, if necessary.

.INPUTS
    String[]]

    The Hostname parameter accepts a string array of public host names.

.OUTPUTS
    System.Management.Automation.PSCustomObject

    The output of this script is a custom object that contains the following properties:

    Subject            - The subject name of the certificate.
    Issuer             - The issuer name of the certificate.
    SerialNumber       - The serial number of the certificate.
    Thumbprint         - The thumbprint of the certificate.
    Issued             - The date and time the certificate is valid from.
    Expires            - The date and time the certificate expires.
    PublicKeyAlgorithm - The public key algorithm used by the certificate.
    KeySize            - The size of the public key in bits.
    SignatureAlgorithm - The signature algorithm used by the certificate.

    If the OutFile parameter is specified, the certificate will be saved to a file in PEM format.

.LINK
    https://github.com/richardhicks/tlscertificate/blob/main/Get-TlsCertificate.ps1

.NOTES
    Version:        2.2.1
    Creation Date:  August 12, 2021
    Last Updated:   February 6, 2026
    Author:         Richard Hicks
    Organization:   Richard M. Hicks Consulting, Inc.
    Contact:        rich@richardhicks.com
    Website:        https://www.richardhicks.com/

#>

[CmdletBinding()]

Param (

    [Parameter(Mandatory, ValueFromPipeline)]
    [string[]]$Hostname,
    [int]$Port = 443,
    [string]$OutFile

)

Process {

    $FileIndex = 1

    ForEach ($Server in $Hostname) {

        # Initialize certificate object
        $Certificate = $Null

        # Create a TCP client object
        $TcpClient = New-Object -TypeName System.Net.Sockets.TcpClient

        # Connect to the remote host
        Try {

            Write-Verbose "Connecting to $Server on port $Port..."
            Try {

                $TcpClient.Connect($Server, $Port)

            }

            Catch {

                Write-Warning "Failed to connect to $Server on port $Port."
                Continue

            }

            # Create a TCP stream object
            $TcpStream = $TcpClient.GetStream()

            # Create an SSL stream object with a validation callback
            $Callback = {

                Param($Source, $Cert, $Chain, [System.Net.Security.SslPolicyErrors]$Errors)
                If ($Errors -ne [System.Net.Security.SslPolicyErrors]::None) {

                    Write-Verbose "Ignoring certificate validation errors: $Errors"

                }

                $True

            }

            $SslStream = New-Object -TypeName System.Net.Security.SslStream -ArgumentList @($TcpStream, $true, $Callback)

            # Retrieve the TLS certificate
            Try {

                Write-Verbose 'Retrieving TLS certificate...'
                $SslStream.AuthenticateAsClient($Server)
                $Certificate = $SslStream.RemoteCertificate

            }

            Catch {

                Write-Warning "Unable to retrieve TLS certificate from $Server."
                Continue

            }

            Finally {

                # Cleanup
                $SslStream.Dispose()

            }

        }

        Finally {

            # Cleanup
            $TcpClient.Dispose()

        }

        # Output certificate properties as an object
        If ($Certificate) {

            If ($Certificate -IsNot [System.Security.Cryptography.X509Certificates.X509Certificate2]) {

                Write-Verbose 'Converting certificate to X509Certificate2 object...'
                $Certificate = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $Certificate

            }

            # Determine key size based on algorithm type
            $KeySize = $null

            # Try to get key size directly (works for RSA)
            If ($Certificate.PublicKey.Key -and $Certificate.PublicKey.Key.KeySize) {

                $KeySize = $Certificate.PublicKey.Key.KeySize

            }

            # For EC certificates, need alternative approach
            ElseIf ($Certificate.PublicKey.Oid.FriendlyName -eq 'ECC' -or $Certificate.PublicKey.Oid.Value -eq '1.2.840.10045.2.1') {

                # Try to get from encoded parameters OID
                If ($Certificate.PublicKey.EncodedParameters -and $Certificate.PublicKey.EncodedParameters.Oid) {

                    $Oid = $Certificate.PublicKey.EncodedParameters.Oid
                    Switch ($Oid.Value) {

                        '1.2.840.10045.3.1.7' { $KeySize = 256 }  # secp256r1 (P-256)
                        '1.3.132.0.34' { $KeySize = 384 }         # secp384r1 (P-384)
                        '1.3.132.0.35' { $KeySize = 521 }         # secp521r1 (P-521)

                        Default {

                            # Try to infer from friendly name
                            If ($Oid.FriendlyName -match '256') { $KeySize = 256 }
                            ElseIf ($Oid.FriendlyName -match '384') { $KeySize = 384 }
                            ElseIf ($Oid.FriendlyName -match '521') { $KeySize = 521 }

                        }

                    }

                }

                # If still null, try to determine from the public key data length
                If (-not $KeySize -and $Certificate.PublicKey.EncodedKeyValue) {

                    $KeyLength = $Certificate.PublicKey.EncodedKeyValue.RawData.Length
                    # EC public keys in uncompressed format: 0x04 + X + Y coordinates
                    Switch ($KeyLength) {

                        65 { $KeySize = 256 }   # P-256: 1 + 32 + 32
                        97 { $KeySize = 384 }   # P-384: 1 + 48 + 48
                        133 { $KeySize = 521 }  # P-521: 1 + 66 + 66
                        # ASN.1 encoded versions (with header bytes)
                        { $_ -in 67, 68, 69 } { $KeySize = 256 }
                        { $_ -in 99, 100, 101 } { $KeySize = 384 }
                        { $_ -in 135, 136, 137 } { $KeySize = 521 }

                    }

                }

            }

            # Create custom object and populate with certificate properties
            $CertObject = [PSCustomObject]@{

                Subject            = $Certificate.Subject
                Issuer             = $Certificate.Issuer
                SerialNumber       = $Certificate.SerialNumber
                Thumbprint         = $Certificate.Thumbprint
                Issued             = $Certificate.NotBefore
                Expires            = $Certificate.NotAfter
                PublicKeyAlgorithm = $Certificate.PublicKey.Oid.FriendlyName
                KeySize            = $KeySize
                SignatureAlgorithm = $Certificate.SignatureAlgorithm.FriendlyName

            }

            # Output certificate details
            $CertObject

            # Save certificate to file if OutFile is specified
            If ($OutFile) {

                $CurrentOutFile = $OutFile

                # If processing multiple host names, append an index to the file name
                If ($Hostname.Count -gt 1) {

                    $FileExtension = [System.IO.Path]::GetExtension($OutFile)
                    $FileNameWithoutExtension = [System.IO.Path]::GetFileNameWithoutExtension($OutFile)
                    $Directory = [System.IO.Path]::GetDirectoryName($OutFile)

                    If (-Not [string]::IsNullOrWhiteSpace($Directory)) {

                        $CurrentOutFile = Join-Path $Directory "$FileNameWithoutExtension$FileIndex$FileExtension"

                    }

                    Else {

                        $CurrentOutFile = "$FileNameWithoutExtension$FileIndex$FileExtension"

                    }

                    $FileIndex++

                }

                Write-Verbose "Saving certificate to $CurrentOutFile..."
                $CertOut = New-Object System.Text.StringBuilder
                [void]($CertOut.AppendLine("-----BEGIN CERTIFICATE-----"))
                [void]($CertOut.AppendLine([System.Convert]::ToBase64String($Certificate.RawData, 1)))
                [void]($CertOut.AppendLine("-----END CERTIFICATE-----"))
                [void]($CertOut.ToString() | Out-File $CurrentOutFile -Encoding ascii -Force)
                Write-Output "Certificate saved to $CurrentOutFile."

            }

        }

    }

}
