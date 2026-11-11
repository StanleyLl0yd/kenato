#Requires -Version 7.0
<#
.SYNOPSIS
  Verify the exact reviewed Go 1.27.3 GitHub artifact on Windows and optionally
  apply it to the EXISTING OCI instance using the operator's SSH config.
.DESCRIPTION
  No secrets are accepted, saved or logged. Without -Apply: local checks only.
  The remote helper itself enforces exact source/ELF pins, health and rollback.
  This does NOT verify public HTTPS or authenticated WSS after deployment.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string] $ArtifactZip,

    [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9_.-]*$')]
    [string] $SshAlias = 'kenato',

    [switch] $Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Fail before reading the artifact or opening SSH for the retired Go 1.27.3 payload.
if ($Apply) {
    throw 'Go 1.27.3 rollout suspended (GO-2026-6859). Require independently approved 1.27.4 source and artifact pins.'
}

$sourceSha = 'aa3bcebe646bd84ce3be0dd4357840ca31acd71d'
$expectedZipSha = '0feebe4644b8650569db9c3cb0fe24595ae16bd61915a14a39f70d2c51aecf0d'
$expectedElfSha = 'c3fda56f38ea3b1e7e8243bfc7a0e72ff819af32052e4a377a177e9b86d54107'
$expectedRootHelperSha = '1cb7f9f8f232ec975d8154ab06d5f115f3a0ca3e9fd4a0ebef2dcf614c41b6cc'
$zipSha = (Get-FileHash -LiteralPath $ArtifactZip -Algorithm SHA256).Hash.ToLowerInvariant()

if ($zipSha -cne $expectedZipSha) {
    throw 'The artifact ZIP does not match the independently verified original GitHub digest.'
}
$stage = Join-Path ([IO.Path]::GetTempPath()) ('kenato-arm64-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($stage) | Out-Null

try {
    Expand-Archive -LiteralPath $ArtifactZip -DestinationPath $stage -ErrorAction Stop
    $expectedFiles = @(
        'kenato-server-linux-arm64',
        'SHA256SUMS',
        'GO_BUILD_INFO.txt',
        'PROVENANCE.txt'
    )
    $actualFiles = @(Get-ChildItem -LiteralPath $stage -File | ForEach-Object Name)
    if (@(Compare-Object $expectedFiles $actualFiles).Count -ne 0) {
        throw 'Unexpected archive contents; expected exactly four verified files.'
    }

    $binary = Join-Path $stage 'kenato-server-linux-arm64'
    $actualElfSha = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualElfSha -cne $expectedElfSha) {
        throw 'The extracted ARM64 binary digest is not the approved original.'
    }
    $sumLine = (Get-Content -LiteralPath (Join-Path $stage 'SHA256SUMS') -Raw).Trim()
    if ($sumLine -cne "$expectedElfSha  kenato-server-linux-arm64") {
        throw 'Unexpected SHA256SUMS contents.'
    }

    $provenance = Get-Content -LiteralPath (Join-Path $stage 'PROVENANCE.txt') -Raw
    $buildInfo = Get-Content -LiteralPath (Join-Path $stage 'GO_BUILD_INFO.txt') -Raw
    foreach ($needle in @("source_sha=$sourceSha", 'source_ref=refs/heads/main', 'goos=linux', 'goarch=arm64', 'cgo_enabled=0')) {
        if (-not $provenance.Contains($needle)) { throw 'Missing source provenance field.' }
    }
    foreach ($needle in @('go1.27.3', "vcs.revision=$sourceSha", 'vcs.modified=false', 'GOOS=linux', 'GOARCH=arm64', 'CGO_ENABLED=0')) {
        if (-not $buildInfo.Contains($needle)) { throw 'Missing Go build verification field.' }
    }

    Write-Output "LOCAL_ARTIFACT_VERIFIED source=$sourceSha binary_sha256=$expectedElfSha"
    if (-not $Apply) {
        Write-Output 'No host changes. Re-run with -Apply only during an authorized maintenance window.'
        return
    }

    foreach ($name in @('ssh', 'scp')) {
        if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
            throw "OpenSSH command missing: $name"
        }
    }
    # Treat a modified local root-executed helper as a supply-chain violation.
    # Normalize Windows line endings before computing the reviewed LF-only hash.
    $localHelper = Join-Path $PSScriptRoot 'rollout_existing_oci_arm64.sh'
    if (-not (Test-Path -LiteralPath $localHelper -PathType Leaf)) {
        throw 'Reviewed remote operator helper is missing next to this PowerShell script.'
    }
    $scriptText = (Get-Content -LiteralPath $localHelper -Raw -Encoding utf8) -replace "`r`n", "`n"
    if ($scriptText.Contains("`r")) {
        throw 'The reviewed shell script has unsupported CR-only line endings.'
    }
    $scriptHash = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($scriptText))
    ).ToLowerInvariant()
    if ($scriptHash -cne $expectedRootHelperSha) {
        throw 'The local root-executed Bash helper differs from the independently reviewed source.'
    }
    Write-Output "REVIEWED_ROOT_HELPER_VERIFIED sha256=$scriptHash"
    $remoteDir = '.kenato-rollout-' + $sourceSha.Substring(0, 12)
    $remotePath = "~/$remoteDir"
    & ssh $SshAlias "umask 077; mkdir -p $remotePath && chmod 700 $remotePath"
    if ($LASTEXITCODE -ne 0) { throw 'Unable to stage files on the existing OCI host.' }

    foreach ($file in @($expectedFiles | ForEach-Object { Join-Path $stage $_ })) {
        & scp -- $file "${SshAlias}:${remoteDir}/"
        if ($LASTEXITCODE -ne 0) { throw 'Secure copy failed; no host deployment command issued.' }
    }

    # Do NOT execute a root script from an unprivileged, mutable SSH home
    # directory. Stream the locally reviewed script directly through the
    # authenticated SSH channel to root bash on stdin (no writable copy).
    # sudo -n deliberately fails closed if host-side approval is missing.
    Write-Output 'Staging completed. Applying reviewed script via non-interactive sudo and SSH stdin.'
    $scriptText | & ssh $SshAlias "sudo -n bash -s -- --apply $remotePath $sourceSha"
    if ($LASTEXITCODE -ne 0) { throw 'Host-side rollout failed; inspect its rollback status before proceeding.' }

    Write-Output 'LOCAL_HOST_ROLLOUT_RETURNED_SUCCESS'
    Write-Output 'PENDING: independent public HTTPS, authenticated WSS and backup/rollback evidence.'
} finally {
    if (Test-Path -LiteralPath $stage) {
        Remove-Item -LiteralPath $stage -Recurse -Force
    }
}
