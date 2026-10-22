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
    [ValidateScript({ Test-Path $_ -PathType Container })]
    [string] $ArtifactDirectory,

    [string] $DeviceSerial,

    [string] $EvidenceDirectory = (Join-Path (Get-Location) 'kenato-m5-device-evidence')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
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
foreach ($fragment in @('application_id=com.sl.kenato.m5probe',
    'status=research_only_no_device_pass_no_voice',
    'not_a_release=true')) {
    if (-not $scope.Contains($fragment)) { throw 'Diagnostic artifact scope is invalid.' }
}
$lines = @(Get-Content -LiteralPath $sumPath)
if ($lines.Count -ne 2) { throw 'Expected exactly two APK checksum records.' }
$hashes = @{}
foreach ($line in $lines) {
    if ($line -cnotmatch '^([0-9a-f]{64})  (app-m5Probe(?:-androidTest)?[.]apk)$') {
        throw 'Noncanonical diagnostic APK SHA256SUMS entry.'
    }
    if ($hashes.ContainsKey($Matches[2])) { throw 'Repeated diagnostic APK checksum.' }
    $hashes[$Matches[2]] = $Matches[1]
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

$api = Invoke-DeviceAdb @('shell', 'getprop', 'ro.build.version.sdk')
$version = Invoke-DeviceAdb @('shell', 'getprop', 'ro.build.version.release')
$patch = Invoke-DeviceAdb @('shell', 'getprop', 'ro.build.version.security_patch')
$emulator = Invoke-DeviceAdb @('shell', 'getprop', 'ro.kernel.qemu')
if ($emulator -eq '1' -or $DeviceSerial.StartsWith('emulator-')) {
    throw 'This script records physical-device evidence only; an emulator is not accepted.'
}
if ($api -notmatch '^\d+$' -or [int]$api -lt 29) {
    throw 'This M5 physical acceptance set requires Android API 29+ (Android 10+).'
}
# Capture only whether a production installation was present, never its path.
$prodBefore = (Invoke-DeviceAdb @('shell', 'pm', 'path', 'com.sl.kenato')) -ne ''
$started = [DateTimeOffset]::UtcNow.ToString('o')
foreach ($name in $expectedNames) {
    $file = Join-Path $ArtifactDirectory $name
    $installed = Invoke-DeviceAdb @('install', '-r', '-t', $file)
    if ($installed -notmatch 'Success') { throw "ADB did not confirm installing $name." }
}
if ((Invoke-DeviceAdb @('shell', 'pm', 'path', 'com.sl.kenato.m5probe')) -eq '' -or
    (Invoke-DeviceAdb @('shell', 'pm', 'path', 'com.sl.kenato.m5probe.test')) -eq '') {
    throw 'Separate diagnostic app and instrumentation packages are not installed.'
}
$output = Invoke-DeviceAdb @('shell', 'am', 'instrument', '-w', '-r', '-e', 'class',
    'com.sl.kenato.session.EpochKeystoreInstrumentedTest',
    'com.sl.kenato.m5probe.test/androidx.test.runner.AndroidJUnitRunner')
$passed = $output -match 'OK \(5 tests\)'
$prodAfter = (Invoke-DeviceAdb @('shell', 'pm', 'path', 'com.sl.kenato')) -ne ''
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
