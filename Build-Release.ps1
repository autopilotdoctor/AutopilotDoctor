<#
.SYNOPSIS
    Packages AutopilotDoctor (Core + HTML Report + WPF GUI) into a single standalone .exe
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$rootDir  = $PSScriptRoot
$srcDir   = Join-Path $rootDir "src"
$distDir  = Join-Path $rootDir "dist"

$coreFile = Join-Path $srcDir "AutopilotDoctor-CoreABCDE.ps1"
$htmlFile = Join-Path $srcDir "New-AutopilotHtmlReport.ps1"
$guiFile  = Join-Path $srcDir "AutopilotDoctor-GUI.ps1"

foreach ($f in @($coreFile, $htmlFile, $guiFile)) {
    if (-not (Test-Path $f)) {
        throw "Required source file missing: $f"
    }
}

if (-not (Test-Path $distDir)) {
    New-Item -ItemType Directory -Path $distDir -Force | Out-Null
}

Write-Host "[1/3] Encoding Core Engine and HTML Report Generator..." -ForegroundColor Cyan
$coreB64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($coreFile))
$htmlB64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($htmlFile))

$guiTemplate = Get-Content -Path $guiFile -Raw -Encoding UTF8
$bundledScript = $guiTemplate.Replace("__EMBEDDED_CORE_B64__", $coreB64).Replace("__EMBEDDED_HTML_B64__", $htmlB64)

$bundledPs1Path = Join-Path $distDir "AutopilotDoctor-Bundled.ps1"
$exeOutPath     = Join-Path $distDir "AutopilotDoctor.exe"

# Save with UTF8 BOM so PowerShell 5.1 always reads encoding cleanly
$utf8Bom = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllText($bundledPs1Path, $bundledScript, $utf8Bom)

Write-Host "[2/3] Checking ps2exe compiler module..." -ForegroundColor Cyan
if (-not (Get-Module -ListAvailable -Name ps2exe)) {
    Write-Host "Installing ps2exe module for current user..." -ForegroundColor Yellow
    Install-Module -Name ps2exe -Scope CurrentUser -Force
}

Import-Module ps2exe

Write-Host "[3/3] Compiling standalone Windows executable ($exeOutPath)..." -ForegroundColor Cyan
Invoke-PS2EXE -InputFile $bundledPs1Path `
              -OutputFile $exeOutPath `
              -NoConsole `
              -RequireAdmin `
              -Title "AutopilotDoctor" `
              -Description "Enterprise Windows Autopilot & Intune Diagnostic Tool" `
              -Product "AutopilotDoctor" `
              -Version "1.3.0.0"

Write-Host "`nSUCCESS! Portable executable ready at: $exeOutPath" -ForegroundColor Green