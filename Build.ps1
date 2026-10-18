param([switch]$SkipTests)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = $PSScriptRoot
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw '.NET Framework 4.8 compiler is required.' }
$dist = Join-Path $root 'dist'
$qa = Join-Path $root '.qa'
New-Item -ItemType Directory -Path $dist,$qa -Force | Out-Null
$sources = @(Get-ChildItem -LiteralPath (Join-Path $root 'src') -Filter '*.cs' | Sort-Object Name | ForEach-Object FullName)
$common = @('/nologo','/optimize+','/platform:x64','/utf8output','/codepage:65001','/r:System.dll','/r:System.Core.dll','/r:System.Drawing.dll','/r:System.Windows.Forms.dll','/r:System.Web.Extensions.dll','/r:System.Management.dll','/r:System.IO.Compression.dll','/r:System.IO.Compression.FileSystem.dll','/r:Microsoft.CSharp.dll')
$resources = @("/resource:$root\assets\split-routing.json,routing.json", "/resource:$root\assets\schema.sql,schema.sql", "/resource:$root\LICENSE.txt,LICENSE.txt", "/resource:$root\THIRD-PARTY.txt,THIRD-PARTY.txt")
$licenseZip = Join-Path $qa 'licenses.zip'
if (Test-Path -LiteralPath $licenseZip) { Remove-Item -LiteralPath $licenseZip }
Compress-Archive -Path (Join-Path $root 'licenses\*') -DestinationPath $licenseZip
$resources += "/resource:$licenseZip,licenses.zip"
$launcher = Join-Path $qa 'AntonVPN.exe'
& $compiler @common '/target:winexe' "/win32manifest:$root\assets\app.manifest" "/out:$launcher" @resources @sources
if ($LASTEXITCODE -ne 0) { throw 'Launcher compilation failed.' }
$payload = Join-Path $root 'assets\client.zip'
$expectedHash = (Get-Content -LiteralPath (Join-Path $root 'assets\client.sha256') -Raw).Trim().ToLowerInvariant()
if ((Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash) { throw 'Official client archive checksum mismatch.' }
$installer = Join-Path $dist 'AntonVPN-Setup-1.0.0.exe'
& $compiler @common '/target:winexe' "/win32manifest:$root\assets\app.manifest" "/out:$installer" @resources "/resource:$launcher,launcher.exe" "/resource:$payload,client.zip" "/resource:$root\assets\client.sha256,client.sha256" @sources
if ($LASTEXITCODE -ne 0) { throw 'Installer compilation failed.' }
if (-not $SkipTests) {
    $testSources = @($sources | Where-Object { [IO.Path]::GetFileName($_) -notin @('Program.cs','AssemblyInfo.cs') })
    $payloadTest = Join-Path $qa 'PayloadTests.exe'
    & $compiler @common '/target:exe' "/out:$payloadTest" @resources "/resource:$launcher,launcher.exe" "/resource:$payload,client.zip" "/resource:$root\assets\client.sha256,client.sha256" @testSources (Join-Path $root 'tests\PayloadTests.cs')
    if ($LASTEXITCODE -ne 0) { throw 'Payload tests compilation failed.' }
    & $payloadTest
    if ($LASTEXITCODE -ne 0) { throw 'Payload tests failed.' }
    $configTest = Join-Path $root 'tests\ConfigTests.cs'
    if (Test-Path -LiteralPath $configTest) {
        $testExe = Join-Path $qa 'ConfigTests.exe'
        & $compiler @common '/target:exe' "/out:$testExe" @resources @testSources $configTest
        if ($LASTEXITCODE -ne 0) { throw 'Tests compilation failed.' }
        & $testExe (Join-Path $qa 'payload')
        if ($LASTEXITCODE -ne 0) { throw 'Configuration tests failed.' }
    }
    $integrationTest = Join-Path $qa 'IntegrationReadOnlySmoke.exe'
    & $compiler @common '/target:exe' "/out:$integrationTest" @resources @testSources (Join-Path $root 'tests\IntegrationReadOnlySmoke.cs')
    if ($LASTEXITCODE -ne 0) { throw 'Integration smoke compilation failed.' }
    & $integrationTest
    if ($LASTEXITCODE -ne 0) { throw 'Integration smoke failed.' }
}
$hash = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $dist 'SHA256SUMS.txt'), "$hash  $([IO.Path]::GetFileName($installer))`n", [Text.UTF8Encoding]::new($false))
Get-Item -LiteralPath $installer | Select-Object FullName,Length
Write-Output "SHA256 $hash"
