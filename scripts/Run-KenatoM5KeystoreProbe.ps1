#Requires -Version 7.0
<#
.SYNOPSIS
  Execute isolated Kenato M5 Keystore device tests, never production voice.
.DESCRIPTION
  Requires extracted, checksum-verified GitHub Actions diagnostic APK artifact.
  Installs only com.sl.kenato.m5probe and its instrumentation package.
  No microphone, network calls, identities, ratchets or production app reset.
  Writes a sanitized PASS/FAIL evidence JSON, never raw logcat or device serial.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string] $ArtifactZip,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-f]{64}

    [Parameter(Mandatory)]
    [string] $ExpectedHeadSha,

    [string] $DeviceSerial,

    [string] $EvidenceDirectory = (Join-Path (Get-Location) 'kenato-m5-device-evidence')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($ExpectedHeadSha -cnotmatch '^[0-9a-f]{40}$') {
    throw 'ExpectedHeadSha must be a lowercase 40-character commit SHA.'
}
if (-not (Get-Command adb -ErrorAction SilentlyContinue)) {
    throw 'Android SDK platform-tools (adb) is required.'
}

# The trust anchor is the ZIP digest from the authenticated GitHub Actions
# artifact metadata, NOT SHA256SUMS or SCOPE.txt inside the ZIP.
$actualZipSha = (Get-FileHash -LiteralPath $ArtifactZip -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualZipSha -cne $ExpectedArtifactZipSha256) {
    throw 'The Actions ZIP does not match the independently verified GitHub artifact digest.'
}
$stage = Join-Path ([IO.Path]::GetTempPath()) ('kenato-keystore-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($stage) | Out-Null
try {
    Expand-Archive -LiteralPath $ArtifactZip -DestinationPath $stage -ErrorAction Stop
    $expectedMembers = @('app-m5Probe.apk', 'app-m5Probe-androidTest.apk', 'SHA256SUMS', 'SCOPE.txt')
    $actualMembers = @(Get-ChildItem -LiteralPath $stage -File | ForEach-Object Name)
    $nested = @(Get-ChildItem -LiteralPath $stage -Directory)
    if ($nested.Count -ne 0 -or @(Compare-Object $expectedMembers $actualMembers).Count -ne 0) {
        throw 'Unexpected Actions ZIP members or nested directories.'
    }
    $ArtifactDirectory = $stage
$expectedNames = @('app-m5Probe.apk', 'app-m5Probe-androidTest.apk')
$sumPath = Join-Path $ArtifactDirectory 'SHA256SUMS'
$scopePath = Join-Path $ArtifactDirectory 'SCOPE.txt'
if (-not (Test-Path -LiteralPath $sumPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $scopePath -PathType Leaf)) {
    throw 'Diagnostic SHA256SUMS or SCOPE.txt is missing.'
}
$scope = Get-Content -LiteralPath $scopePath -Raw
$scopeLines = @($scope -split '\r?\n' | Where-Object { $_ -ne '' })
$heads = @($scopeLines | Where-Object { $_ -clike 'pr_head_sha=*' })
$checkouts = @($scopeLines | Where-Object { $_ -clike 'checked_out_sha=*' })
if ($scopeLines.Count -ne 5 -or $heads.Count -ne 1 -or
    $heads[0] -cne "pr_head_sha=$ExpectedHeadSha" -or
    $checkouts.Count -ne 1 -or
    $checkouts[0] -cnotmatch '^checked_out_sha=[0-9a-f]{40}$') {
    throw 'Artifact PR HEAD does not match the reviewed commit.'
}
foreach ($fragment in @('application_id=com.sl.kenato.m5probe',
    'status=research_only_no_device_pass_no_voice',
    'not_a_release=true')) {
    if (-not $scope.Contains($fragment)) { throw 'Diagnostic artifact scope is invalid.' }
}
$lines = @(Get-Content -LiteralPath $sumPath)
if ($lines.Count -ne 2) { throw 'Expected exactly two APK checksum records.' }
$hashes = @{}
foreach ($line in $lines) {
    if ($line -cmatch '^([0-9a-f]{64})  (app-m5Probe(?:-androidTest)?[.]apk)$') {
        $name = $Matches[2]
        $digest = $Matches[1]
    } else {
        throw 'Noncanonical diagnostic APK SHA256SUMS entry.'
    }
    if ($hashes.ContainsKey($name)) { throw 'Repeated diagnostic APK checksum.' }
    $hashes[$name] = $digest
}
foreach ($name in $expectedNames) {
    if (-not $hashes.ContainsKey($name)) { throw "Missing checksum for $name" }
    $file = Join-Path $ArtifactDirectory $name
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing $name" }
    if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hashes[$name]) {
        throw "SHA256 mismatch for $name"
    }
}

if ([string]::IsNullOrWhiteSpace($DeviceSerial)) {
    $available = @(& adb devices | Where-Object { $_ -match '^([^\s]+)\s+device$' } |
        ForEach-Object { ($_.Trim() -split '\s+')[0] })
    if ($LASTEXITCODE -ne 0 -or $available.Count -ne 1) {
        throw 'Connect and authorize exactly one physical Android device or specify -DeviceSerial.'
    }
    $DeviceSerial = [string]$available[0]
}
if ($DeviceSerial -notmatch '^[A-Za-z0-9.:_-]+$') { throw 'Invalid ADB device serial.' }

function Invoke-DeviceAdb([string[]] $Arguments) {
    $output = @(& adb -s $DeviceSerial @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "ADB command failed; check device authorization and operation (exit=$LASTEXITCODE)."
    }
    return ($output -join "`n").Trim()
}

$api = Invoke-DeviceAdb -Arguments @('shell', 'getprop', 'ro.build.version.sdk')
$version = Invoke-DeviceAdb -Arguments @('shell', 'getprop', 'ro.build.version.release')
$patch = Invoke-DeviceAdb -Arguments @('shell', 'getprop', 'ro.build.version.security_patch')
$emulator = Invoke-DeviceAdb -Arguments @('shell', 'getprop', 'ro.kernel.qemu')
if ($emulator -eq '1' -or $DeviceSerial.StartsWith('emulator-')) {
    throw 'This script records physical-device evidence only; an emulator is not accepted.'
}
if ($api -notmatch '^\d+$' -or [int]$api -lt 29) {
    throw 'This M5 physical acceptance set requires Android API 29+ (Android 10+).'
}
# Capture only whether a production installation was present, never its path.
$prodBefore = (Invoke-DeviceAdb -Arguments @('shell', 'pm', 'path', 'com.sl.kenato')) -ne ''
$started = [DateTimeOffset]::UtcNow.ToString('o')
foreach ($name in $expectedNames) {
    $file = Join-Path $ArtifactDirectory $name
    $installed = Invoke-DeviceAdb -Arguments @('install', '-r', '-t', $file)
    if ($installed -notmatch 'Success') { throw "ADB did not confirm installing $name." }
}
if ((Invoke-DeviceAdb -Arguments @('shell', 'pm', 'path', 'com.sl.kenato.m5probe')) -eq '' -or
    (Invoke-DeviceAdb -Arguments @('shell', 'pm', 'path', 'com.sl.kenato.m5probe.test')) -eq '') {
    throw 'Separate diagnostic app and instrumentation packages are not installed.'
}
$output = Invoke-DeviceAdb -Arguments @('shell', 'am', 'instrument', '-w', '-r', '-e', 'class',
    'com.sl.kenato.session.EpochKeystoreInstrumentedTest',
    'com.sl.kenato.m5probe.test/androidx.test.runner.AndroidJUnitRunner')
$passed = $output -match 'OK \(5 tests\)'
$prodAfter = (Invoke-DeviceAdb -Arguments @('shell', 'pm', 'path', 'com.sl.kenato')) -ne ''
if ($prodBefore -ne $prodAfter) { throw 'Unexpected production package-presence change.' }

# Never write instrumentation stdout, logcat, APK signing keys, device IDs,
# contact identity data, private addresses or QR proofs to evidence artifacts.
$serialSha = [System.Security.Cryptography.SHA256]::HashData(
    [Text.Encoding]::UTF8.GetBytes($DeviceSerial)
)
$evidence = [ordered]@{
    result = if ($passed) { 'PASS' } else { 'FAIL' }
    executed_expected = 5
    passed_expected = if ($passed) { 5 } else { 0 }
    android_api = [int]$api
    android_version = $version
    security_patch = $patch
    serial_sha256_prefix = [Convert]::ToHexString($serialSha).Substring(0, 12).ToLowerInvariant()
    production_package_present_before_and_after = $prodBefore
    package = 'com.sl.kenato.m5probe'
    reviewed_pr_head_sha = $ExpectedHeadSha
    artifact_zip_sha256 = $ExpectedArtifactZipSha256
    probe_sha256 = $hashes['app-m5Probe.apk']
    instrument_sha256 = $hashes['app-m5Probe-androidTest.apk']
    started_utc = $started
    finished_utc = [DateTimeOffset]::UtcNow.ToString('o')
    scope = 'isolated Keystore synthetic acceptance only; no voice/media'
}
[IO.Directory]::CreateDirectory($EvidenceDirectory) | Out-Null
$name = 'kenato-keystore-api' + $api + '-' + ([DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ')) + '.json'
$destination = Join-Path $EvidenceDirectory $name
$evidence | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $destination -Encoding utf8
Write-Output "M5_KEYSTORE_$($evidence.result) API=$api; sanitized evidence: $destination"
if (-not $passed) {
    throw 'Instrumented test suite did not report exactly OK (5 tests); physical gate remains BLOCKED.'
}
)]
    [string] $ExpectedArtifactZipSha256,

    [Parameter(Mandatory)]
    [string] $ExpectedHeadSha,

    [string] $DeviceSerial,

    [string] $EvidenceDirectory = (Join-Path (Get-Location) 'kenato-m5-device-evidence')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($ExpectedHeadSha -cnotmatch '^[0-9a-f]{40}$') {
    throw 'ExpectedHeadSha must be a lowercase 40-character commit SHA.'
}
if (-not (Get-Command adb -ErrorAction SilentlyContinue)) {
    throw 'Android SDK platform-tools (adb) is required.'
}

$expectedNames = @('app-m5Probe.apk', 'app-m5Probe-androidTest.apk')
$sumPath = Join-Path $ArtifactDirectory 'SHA256SUMS'
$scopePath = Join-Path $ArtifactDirectory 'SCOPE.txt'
if (-not (Test-Path -LiteralPath $sumPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $scopePath -PathType Leaf)) {
    throw 'Diagnostic SHA256SUMS or SCOPE.txt is missing.'
}
$scope = Get-Content -LiteralPath $scopePath -Raw
$scopeLines = @($scope -split '\r?\n' | Where-Object { $_ -ne '' })
$heads = @($scopeLines | Where-Object { $_ -clike 'pr_head_sha=*' })
$checkouts = @($scopeLines | Where-Object { $_ -clike 'checked_out_sha=*' })
if ($scopeLines.Count -ne 5 -or $heads.Count -ne 1 -or
    $heads[0] -cne "pr_head_sha=$ExpectedHeadSha" -or
    $checkouts.Count -ne 1 -or
    $checkouts[0] -cnotmatch '^checked_out_sha=[0-9a-f]{40}$') {
    throw 'Artifact PR HEAD does not match the reviewed commit.'
}
foreach ($fragment in @('application_id=com.sl.kenato.m5probe',
    'status=research_only_no_device_pass_no_voice',
    'not_a_release=true')) {
    if (-not $scope.Contains($fragment)) { throw 'Diagnostic artifact scope is invalid.' }
}
$lines = @(Get-Content -LiteralPath $sumPath)
if ($lines.Count -ne 2) { throw 'Expected exactly two APK checksum records.' }
$hashes = @{}
foreach ($line in $lines) {
    if ($line -cmatch '^([0-9a-f]{64})  (app-m5Probe(?:-androidTest)?[.]apk)$') {
        $name = $Matches[2]
        $digest = $Matches[1]
    } else {
        throw 'Noncanonical diagnostic APK SHA256SUMS entry.'
    }
    if ($hashes.ContainsKey($name)) { throw 'Repeated diagnostic APK checksum.' }
    $hashes[$name] = $digest
}
foreach ($name in $expectedNames) {
    if (-not $hashes.ContainsKey($name)) { throw "Missing checksum for $name" }
    $file = Join-Path $ArtifactDirectory $name
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing $name" }
    if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hashes[$name]) {
        throw "SHA256 mismatch for $name"
    }
}

if ([string]::IsNullOrWhiteSpace($DeviceSerial)) {
    $available = @(& adb devices | Where-Object { $_ -match '^([^\s]+)\s+device$' } |
        ForEach-Object { ($_.Trim() -split '\s+')[0] })
    if ($LASTEXITCODE -ne 0 -or $available.Count -ne 1) {
        throw 'Connect and authorize exactly one physical Android device or specify -DeviceSerial.'
    }
    $DeviceSerial = [string]$available[0]
}
if ($DeviceSerial -notmatch '^[A-Za-z0-9.:_-]+$') { throw 'Invalid ADB device serial.' }

function Invoke-DeviceAdb([string[]] $Arguments) {
    $output = @(& adb -s $DeviceSerial @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "ADB command failed; check device authorization and operation (exit=$LASTEXITCODE)."
    }
    return ($output -join "`n").Trim()
}

$api = Invoke-DeviceAdb -Arguments @('shell', 'getprop', 'ro.build.version.sdk')
$version = Invoke-DeviceAdb -Arguments @('shell', 'getprop', 'ro.build.version.release')
$patch = Invoke-DeviceAdb -Arguments @('shell', 'getprop', 'ro.build.version.security_patch')
$emulator = Invoke-DeviceAdb -Arguments @('shell', 'getprop', 'ro.kernel.qemu')
if ($emulator -eq '1' -or $DeviceSerial.StartsWith('emulator-')) {
    throw 'This script records physical-device evidence only; an emulator is not accepted.'
}
if ($api -notmatch '^\d+$' -or [int]$api -lt 29) {
    throw 'This M5 physical acceptance set requires Android API 29+ (Android 10+).'
}
# Capture only whether a production installation was present, never its path.
$prodBefore = (Invoke-DeviceAdb -Arguments @('shell', 'pm', 'path', 'com.sl.kenato')) -ne ''
$started = [DateTimeOffset]::UtcNow.ToString('o')
foreach ($name in $expectedNames) {
    $file = Join-Path $ArtifactDirectory $name
    $installed = Invoke-DeviceAdb -Arguments @('install', '-r', '-t', $file)
    if ($installed -notmatch 'Success') { throw "ADB did not confirm installing $name." }
}
if ((Invoke-DeviceAdb -Arguments @('shell', 'pm', 'path', 'com.sl.kenato.m5probe')) -eq '' -or
    (Invoke-DeviceAdb -Arguments @('shell', 'pm', 'path', 'com.sl.kenato.m5probe.test')) -eq '') {
    throw 'Separate diagnostic app and instrumentation packages are not installed.'
}
$output = Invoke-DeviceAdb -Arguments @('shell', 'am', 'instrument', '-w', '-r', '-e', 'class',
    'com.sl.kenato.session.EpochKeystoreInstrumentedTest',
    'com.sl.kenato.m5probe.test/androidx.test.runner.AndroidJUnitRunner')
$passed = $output -match 'OK \(5 tests\)'
$prodAfter = (Invoke-DeviceAdb -Arguments @('shell', 'pm', 'path', 'com.sl.kenato')) -ne ''
if ($prodBefore -ne $prodAfter) { throw 'Unexpected production package-presence change.' }

# Never write instrumentation stdout, logcat, APK signing keys, device IDs,
# contact identity data, private addresses or QR proofs to evidence artifacts.
$serialSha = [System.Security.Cryptography.SHA256]::HashData(
    [Text.Encoding]::UTF8.GetBytes($DeviceSerial)
)
$evidence = [ordered]@{
    result = if ($passed) { 'PASS' } else { 'FAIL' }
    executed_expected = 5
    passed_expected = if ($passed) { 5 } else { 0 }
    android_api = [int]$api
    android_version = $version
    security_patch = $patch
    serial_sha256_prefix = [Convert]::ToHexString($serialSha).Substring(0, 12).ToLowerInvariant()
    production_package_present_before_and_after = $prodBefore
    package = 'com.sl.kenato.m5probe'
    reviewed_pr_head_sha = $ExpectedHeadSha
    probe_sha256 = $hashes['app-m5Probe.apk']
    instrument_sha256 = $hashes['app-m5Probe-androidTest.apk']
    started_utc = $started
    finished_utc = [DateTimeOffset]::UtcNow.ToString('o')
    scope = 'isolated Keystore synthetic acceptance only; no voice/media'
}
[IO.Directory]::CreateDirectory($EvidenceDirectory) | Out-Null
$name = 'kenato-keystore-api' + $api + '-' + ([DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ')) + '.json'
$destination = Join-Path $EvidenceDirectory $name
$evidence | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $destination -Encoding utf8
Write-Output "M5_KEYSTORE_$($evidence.result) API=$api; sanitized evidence: $destination"
if (-not $passed) {
    throw 'Instrumented test suite did not report exactly OK (5 tests); physical gate remains BLOCKED.'
}

} finally {
    if (Test-Path -LiteralPath $stage) {
        Remove-Item -LiteralPath $stage -Recurse -Force
    }
}
