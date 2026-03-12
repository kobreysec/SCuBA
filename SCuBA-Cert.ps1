$ErrorActionPreference = "Stop"

$certname = "KobReySecSCuBA"
$workdir  = "C:\Users\$env:USERNAME\Certificate"

New-Item -ItemType Directory -Path $workdir -Force | Out-Null
Set-Location $workdir

$cerPath       = Join-Path $workdir "$certname.cer"
$pfxPath       = Join-Path $workdir "$certname.pfx"
$keyPath       = Join-Path $workdir "$certname.key"
$certPemPath   = Join-Path $workdir "$certname-cert.pem"
$bundlePemPath = Join-Path $workdir "$certname-bundle.pem"

$passwordPlain  = "TempPassword123!"
$passwordSecure = ConvertTo-SecureString -String $passwordPlain -Force -AsPlainText

Write-Host "Creating self-signed certificate..."
$cert = New-SelfSignedCertificate `
  -Subject "CN=$certname" `
  -CertStoreLocation "Cert:\CurrentUser\My" `
  -KeyExportPolicy Exportable `
  -KeySpec Signature `
  -KeyLength 2048 `
  -KeyAlgorithm RSA `
  -HashAlgorithm SHA256

Write-Host "Exporting public certificate (.cer)..."
Export-Certificate `
  -Cert $cert `
  -FilePath $cerPath | Out-Null

Write-Host "Exporting PFX with private key..."
Export-PfxCertificate `
  -Cert $cert `
  -FilePath $pfxPath `
  -Password $passwordSecure | Out-Null

Add-Type -AssemblyName System.Security

$flags =
    [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable `
    -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet `
    -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet

Write-Host "Loading PFX and extracting private key..."
$certWithKey = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$certWithKey.Import($pfxPath, $passwordPlain, $flags)

if (-not $certWithKey.HasPrivateKey) {
    throw "The imported PFX does not contain a private key."
}

$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certWithKey)

if (-not $rsa) {
    throw "Could not retrieve RSA private key from certificate."
}

$keyBytes = $null

$exportPkcs8 = $rsa.GetType().GetMethod("ExportPkcs8PrivateKey", [Type[]]@())
if ($exportPkcs8) {
    $keyBytes = $exportPkcs8.Invoke($rsa, @())
}
elseif ($rsa -is [System.Security.Cryptography.RSACng]) {
    $keyBytes = $rsa.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
}
else {
    throw "This PowerShell/.NET version cannot export the private key directly to PKCS#8 PEM."
}

if (-not $keyBytes) {
    throw "Private key export returned no data."
}

$base64Key = [Convert]::ToBase64String($keyBytes)
$keyLines = New-Object System.Collections.Generic.List[string]
for ($i = 0; $i -lt $base64Key.Length; $i += 64) {
    $remaining = $base64Key.Length - $i
    $take = [Math]::Min(64, $remaining)
    $keyLines.Add($base64Key.Substring($i, $take))
}

$keyPem = @(
    "-----BEGIN PRIVATE KEY-----"
    $keyLines
    "-----END PRIVATE KEY-----"
) -join [Environment]::NewLine

[System.IO.File]::WriteAllText($keyPath, $keyPem)

Write-Host "Converting certificate to PEM..."
$certOnly = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cerPath)
$base64Cert = [Convert]::ToBase64String($certOnly.RawData)
$certLines = New-Object System.Collections.Generic.List[string]
for ($i = 0; $i -lt $base64Cert.Length; $i += 64) {
    $remaining = $base64Cert.Length - $i
    $take = [Math]::Min(64, $remaining)
    $certLines.Add($base64Cert.Substring($i, $take))
}

$certPem = @(
    "-----BEGIN CERTIFICATE-----"
    $certLines
    "-----END CERTIFICATE-----"
) -join [Environment]::NewLine

[System.IO.File]::WriteAllText($certPemPath, $certPem)

Write-Host "Building bundle PEM for Nessus..."
$bundlePem = $keyPem + [Environment]::NewLine + $certPem + [Environment]::NewLine
[System.IO.File]::WriteAllText($bundlePemPath, $bundlePem)

Write-Host ""
Write-Host "Created files:"
Write-Host "  $cerPath"
Write-Host "  $pfxPath"
Write-Host "  $keyPath"
Write-Host "  $certPemPath"
Write-Host "  $bundlePemPath"
Write-Host ""

$thumbprint = $certOnly.Thumbprint
Write-Host "Certificate thumbprint:"
Write-Host "  $thumbprint"
Write-Host ""
Write-Host "Use in Azure App Registration:"
Write-Host "  $certname.cer"
Write-Host ""
Write-Host "Send this to KobReySec:"
Write-Host "  $certname-bundle.pem"