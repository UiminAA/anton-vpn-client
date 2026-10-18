[CmdletBinding()]
param(
    [string]$CachedZip,
    [switch]$Offline
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$assetRoot = Join-Path $projectRoot 'assets'
$version = '7.25.4'
$assetName = 'v2rayN-windows-64-desktop.zip'
$expectedHash = 'CCCF12BE605CE947CB7C4646BFA77A98F680F099F4BF2D76C6A5FEE4D2EB3820'
$expectedBytes = 143961123
$downloadUri = "https://github.com/2dust/v2rayN/releases/download/$version/$assetName"
$destination = Join-Path $assetRoot 'client.zip'

if (-not $Offline) {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/2dust/v2rayN/releases/tags/$version"
    $asset = @($release.assets | Where-Object { $_.name -eq $assetName })
    if ($asset.Count -ne 1 -or $asset[0].digest -ne ('sha256:' + $expectedHash.ToLowerInvariant()) -or $asset[0].size -ne $expectedBytes) {
        throw 'Official release metadata does not match the pinned payload.'
    }
}

New-Item -ItemType Directory -Path $assetRoot -Force | Out-Null
$candidate = $null
foreach ($path in @($CachedZip, $destination, (Join-Path $env:TEMP "v2rayN-$version-windows-64-desktop.zip"))) {
    if ($path -and (Test-Path -LiteralPath $path -PathType Leaf)) {
        if ((Get-Item -LiteralPath $path).Length -eq $expectedBytes -and (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -eq $expectedHash) {
            $candidate = (Resolve-Path -LiteralPath $path).Path
            break
        }
    }
}
if (-not $candidate) {
    if ($Offline) { throw 'No cached official payload passed SHA-256 verification.' }
    $temporaryZip = Join-Path $assetRoot ('client-' + [Guid]::NewGuid().ToString('N') + '.download')
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUri -OutFile $temporaryZip
        if ((Get-Item -LiteralPath $temporaryZip).Length -ne $expectedBytes -or (Get-FileHash -LiteralPath $temporaryZip -Algorithm SHA256).Hash -ne $expectedHash) {
            throw 'Downloaded payload failed SHA-256 verification.'
        }
        Move-Item -LiteralPath $temporaryZip -Destination $destination -Force
        $candidate = $destination
    } finally {
        if (Test-Path -LiteralPath $temporaryZip) { Remove-Item -LiteralPath $temporaryZip -Force }
    }
}
if ($candidate -ne $destination) { Copy-Item -LiteralPath $candidate -Destination $destination -Force }

Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::OpenRead($destination)
try {
    foreach ($name in @('v2rayN.exe', 'e_sqlite3.dll', 'bin/sing_box/sing-box.exe', 'bin/sing_box/libcronet.dll')) {
        if (-not $archive.GetEntry('v2rayN-windows-64/' + $name)) { throw "Missing required upstream file: $name" }
    }
    foreach ($entry in $archive.Entries) {
        if ($entry.FullName -notmatch '^v2rayN-windows-64/' -or $entry.FullName -match '(^|/)(\.\.|guiConfigs|guiLogs|binConfigs|backups)(/|$)') {
            throw 'Unexpected or personal entry in upstream archive.'
        }
    }
    foreach ($name in @('v2rayN.exe', 'e_sqlite3.dll')) {
        $entry = $archive.GetEntry('v2rayN-windows-64/' + $name)
        $memory = New-Object IO.MemoryStream
        $stream = $entry.Open()
        try { $stream.CopyTo($memory) } finally { $stream.Dispose() }
        $bytes = $memory.ToArray()
        $memory.Dispose()
        $headerOffset = [BitConverter]::ToInt32($bytes, 0x3C)
        if ([BitConverter]::ToUInt16($bytes, $headerOffset + 4) -ne 0x8664) { throw "Not a Windows x64 payload: $name" }
    }
} finally { $archive.Dispose() }

[IO.File]::WriteAllText((Join-Path $assetRoot 'client.sha256'), ($expectedHash.ToLowerInvariant() + [Environment]::NewLine), (New-Object Text.UTF8Encoding($false)))
Write-Output "VERIFIED v2rayN $version Windows x64: $expectedBytes bytes; SHA256 $expectedHash"
