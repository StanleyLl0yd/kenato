#Requires -Version 7.0
<#
.SYNOPSIS
  Verify the exact reviewed Go 1.27.2 GitHub artifact on Windows and optionally
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

    [ValidatePattern('^[a-zA-Z0-9_.-]+$')]
    [string] $SshAlias = 'kenato',

    [switch] $Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$sourceSha = '04f8d78c3d730d512a9bca6462a4f4177db6ff58'
$expectedZipSha = '9e0a95b00e8d81078e49e71a7a72788af3829420991098b3b72c2ef01dbb7811'
$expectedElfSha = 'f651a2519ea555d224f49897944561447dd6a8810353dd34c4e87f5ff28b97e9'
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
    foreach ($needle in @('go1.27.2', "vcs.revision=$sourceSha", 'vcs.modified=false', 'GOOS=linux', 'GOARCH=arm64', 'CGO_ENABLED=0')) {
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
    $remoteDir = '.kenato-rollout-' + $sourceSha.Substring(0, 12)
    $remotePath = "~/$remoteDir"
    & ssh $SshAlias "umask 077; mkdir -p $remotePath && chmod 700 $remotePath"
    if ($LASTEXITCODE -ne 0) { throw 'Unable to stage files on the existing OCI host.' }

    $localHelper = Join-Path $PSScriptRoot 'rollout_existing_oci_arm64.sh'
    if (-not (Test-Path -LiteralPath $localHelper -PathType Leaf)) {
        throw 'Reviewed remote operator helper is missing next to this PowerShell script.'
    }
    foreach ($file in @($localHelper) + @($expectedFiles | ForEach-Object { Join-Path $stage $_ })) {
        & scp -- $file "${SshAlias}:${remoteDir}/"
        if ($LASTEXITCODE -ne 0) { throw 'Secure copy failed; no host deployment command issued.' }
    }

    Write-Output 'Staging completed. Running the reviewed host-side update with automatic local rollback.'
    & ssh -tt $SshAlias "sudo bash $remotePath/rollout_existing_oci_arm64.sh --apply $remotePath $sourceSha"
    if ($LASTEXITCODE -ne 0) { throw 'Host-side rollout failed; inspect its rollback status before proceeding.' }

    Write-Output 'LOCAL_HOST_ROLLOUT_RETURNED_SUCCESS'
    Write-Output 'PENDING: independent public HTTPS, authenticated WSS and backup/rollback evidence.'
} finally {
    if (Test-Path -LiteralPath $stage) {
        Remove-Item -LiteralPath $stage -Recurse -Force
    }
}
