<#
.SYNOPSIS
    AutopilotDoctor Desktop GUI & Gumroad Licensing Wrapper
.DESCRIPTION
    Provides a modern WPF interface, background non-blocking diagnostic execution,
    Freemium/Pro/MSP feature gating via Gumroad License API, 30-day offline grace cache,
    and one-click HTML report launch.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

# Build-Release.ps1 populates these Base64 strings when compiling into a single .exe
$script:EmbeddedCoreBase64 = "__EMBEDDED_CORE_B64__"
$script:EmbeddedHtmlBase64 = "__EMBEDDED_HTML_B64__"

# Gumroad Store & Licensing Configuration (Populate after creating the Gumroad product)
$script:GumroadVerifyUrl   = "https://api.gumroad.com/v2/licenses/verify"
$script:GumroadProductId   = "t7JXjnQWLgkSP74YW1itIA=="
$script:CheckoutUrl        = "https://autopilotdoctor.gumroad.com/l/qtryi"
$script:OfflineGraceDays   = 30

$script:AppDataDir     = Join-Path $env:LOCALAPPDATA "AutopilotDoctor"
$script:LicenseFile    = Join-Path $script:AppDataDir "license.json"
$script:ReportDir      = Join-Path ([Environment]::GetFolderPath("Desktop")) "AutopilotDoctor-Reports"
$script:CurrentLicense = $null

if (-not (Test-Path $script:AppDataDir)) {
    New-Item -ItemType Directory -Path $script:AppDataDir -Force | Out-Null
}

#region Licensing Engine (Gumroad License API + 30-Day Offline Grace Cache)

function Get-LicenseStatus {
    if (-not (Test-Path $script:LicenseFile)) {
        return [PSCustomObject]@{
            IsPro        = $false
            LicenseKey   = ""
            TierName     = "Free"
            StatusText   = "Free Edition (Remediation hints locked)"
            LastVerified = $null
        }
    }

    try {
        $licData = Get-Content -Path $script:LicenseFile -Raw -Encoding UTF8 | ConvertFrom-Json
        if (-not $licData -or
            -not $licData.PSObject.Properties['licenseKey'] -or
            -not $licData.PSObject.Properties['lastVerifiedUtc'] -or
            [string]::IsNullOrWhiteSpace($licData.licenseKey) -or
            [string]::IsNullOrWhiteSpace($licData.lastVerifiedUtc)) {
            throw "Invalid license cache structure"
        }

        $lastVerified = [DateTime]::Parse($licData.lastVerifiedUtc).ToUniversalTime()
        $daysSinceCheck = ((Get-Date).ToUniversalTime() - $lastVerified).TotalDays

        # Re-verify online if > 7 days old (without incrementing seat usage count)
        if ($daysSinceCheck -gt 7 -and $daysSinceCheck -le $script:OfflineGraceDays -and $script:GumroadProductId -notmatch '^__GUMROAD_') {
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $body = @{
                    product_id           = $script:GumroadProductId
                    license_key          = $licData.licenseKey
                    increment_uses_count = "false"
                }
                $resp = Invoke-RestMethod -Uri $script:GumroadVerifyUrl -Method Post -Body $body -TimeoutSec 6 -ErrorAction Stop

                $isSuccess = ($resp.PSObject.Properties['success'] -and $resp.success -eq $true)
                $isRefunded = $false
                if ($resp.PSObject.Properties['purchase'] -and $resp.purchase) {
                    if (($resp.purchase.PSObject.Properties['refunded'] -and $resp.purchase.refunded -eq $true) -or
                        ($resp.purchase.PSObject.Properties['chargebacked'] -and $resp.purchase.chargebacked -eq $true)) {
                        $isRefunded = $true
                    }
                }

                if ($isSuccess -and -not $isRefunded) {
                    $licData.lastVerifiedUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                    $licData | ConvertTo-Json | Out-File -FilePath $script:LicenseFile -Encoding UTF8 -Force
                } else {
                    Remove-Item -Path $script:LicenseFile -Force -ErrorAction SilentlyContinue
                    return [PSCustomObject]@{
                        IsPro        = $false
                        LicenseKey   = ""
                        TierName     = "Free"
                        StatusText   = "License Revoked / Refunded"
                        LastVerified = $null
                    }
                }
            } catch {
                # Offline or OOBE restricted network: allow within 30-day grace window
            }
        } elseif ($daysSinceCheck -gt $script:OfflineGraceDays) {
            return [PSCustomObject]@{
                IsPro        = $false
                LicenseKey   = $licData.licenseKey
                TierName     = "Free"
                StatusText   = "Offline Grace Expired (Connect to internet to re-validate)"
                LastVerified = $licData.lastVerifiedUtc
            }
        }

        $maskedKey = if ($licData.licenseKey.Length -ge 8) {
            $licData.licenseKey.Substring(0, 4) + "-****-****-" + $licData.licenseKey.Substring($licData.licenseKey.Length - 4)
        } else {
            "ACTIVE"
        }

        $tierLabel = if ($licData.PSObject.Properties['tierName'] -and -not [string]::IsNullOrWhiteSpace($licData.tierName)) {
            $licData.tierName
        } else {
            "PRO"
        }

        return [PSCustomObject]@{
            IsPro        = $true
            LicenseKey   = $licData.licenseKey
            TierName     = $tierLabel
            StatusText   = "$tierLabel Edition Active ($maskedKey)"
            LastVerified = $licData.lastVerifiedUtc
        }
    } catch {
        return [PSCustomObject]@{
            IsPro        = $false
            LicenseKey   = ""
            TierName     = "Free"
            StatusText   = "Free Edition (Remediation hints locked)"
            LastVerified = $null
        }
    }
}

function Invoke-LicenseActivation {
    param (
        [string]$KeyInput
    )

    $cleanKey = $KeyInput.Trim()
    if ([string]::IsNullOrWhiteSpace($cleanKey)) {
        return [PSCustomObject]@{ Success = $false; Message = "Please enter a valid license key." }
    }

    if ($script:GumroadProductId -match '^__GUMROAD_') {
        return [PSCustomObject]@{ Success = $false; Message = "Store Product ID is not configured in this build yet." }
    }

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $body = @{
            product_id           = $script:GumroadProductId
            license_key          = $cleanKey
            increment_uses_count = "true"
        }

        $response = Invoke-RestMethod -Uri $script:GumroadVerifyUrl -Method Post -Body $body -TimeoutSec 12 -ErrorAction Stop

        if ($response.PSObject.Properties['success'] -and $response.success -eq $true) {
            $isRefunded = $false
            $variantText = ""

            if ($response.PSObject.Properties['purchase'] -and $response.purchase) {
                $purchase = $response.purchase
                if (($purchase.PSObject.Properties['refunded'] -and $purchase.refunded -eq $true) -or
                    ($purchase.PSObject.Properties['chargebacked'] -and $purchase.chargebacked -eq $true)) {
                    $isRefunded = $true
                }
                if ($purchase.PSObject.Properties['variants'] -and $purchase.variants) {
                    $variantText = [string]$purchase.variants
                }
            }

            if ($isRefunded) {
                return [PSCustomObject]@{ Success = $false; Message = "This license key has been refunded or revoked." }
            }

            $isMsp    = $variantText -match "MSP"
            $maxSeats = if ($isMsp) { 15 } else { 3 }
            $tierName = if ($isMsp) { "MSP" } else { "PRO" }

            $currentUses = if ($response.PSObject.Properties['uses']) { [int]$response.uses } else { 1 }
            if ($currentUses -gt $maxSeats) {
                return [PSCustomObject]@{
                    Success = $false
                    Message = "Activation limit reached ($maxSeats workstations max for $tierName license)."
                }
            }

            $cacheObj = [PSCustomObject]@{
                licenseKey      = $cleanKey
                tierName        = $tierName
                maxSeats        = $maxSeats
                lastVerifiedUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            }
            $cacheObj | ConvertTo-Json | Out-File -FilePath $script:LicenseFile -Encoding UTF8 -Force

            return [PSCustomObject]@{
                Success = $true
                Message = "AutopilotDoctor $tierName activated successfully! (Seat $currentUses of $maxSeats)"
            }
        } else {
            $errMsg = if ($response.PSObject.Properties['message']) { $response.message } else { "Invalid license key." }
            return [PSCustomObject]@{ Success = $false; Message = $errMsg }
        }
    } catch {
        $detail = "Invalid or unrecognized license key."
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            try {
                $errJson = $_.ErrorDetails.Message | ConvertFrom-Json
                if ($errJson.PSObject.Properties['message']) { $detail = $errJson.message }
            } catch {}
        } elseif ($_.Exception.Message -notmatch "404") {
            $detail = "Network or API error: $($_.Exception.Message)"
        }
        return [PSCustomObject]@{ Success = $false; Message = $detail }
    }
}

#endregion

#region WPF XAML UI Definition

[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="AutopilotDoctor v1.3 - Enterprise Diagnostics"
        Height="560" Width="680"
        WindowStartupLocation="CenterScreen"
        ResizeMode="CanMinimize"
        Background="#0B0F19" Foreground="#F3F4F6"
        FontFamily="Segoe UI">

    <Window.Resources>
        <Style TargetType="Button">
            <Setter Property="Background" Value="#1F2937"/>
            <Setter Property="Foreground" Value="#F3F4F6"/>
            <Setter Property="BorderBrush" Value="#374151"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="14,8"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="6" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="BorderBrush" Value="#3B82F6"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Opacity" Value="0.5"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>

    <Grid Margin="22">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- Header -->
        <Border Grid.Row="0" Background="#111827" BorderBrush="#283548" BorderThickness="1" CornerRadius="10" Padding="16" Margin="0,0,0,14">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>

                <Border Grid.Column="0" Width="44" Height="44" CornerRadius="9" Background="#2563EB" Margin="0,0,14,0">
                    <TextBlock Text="AD" FontSize="18" FontWeight="Bold" Foreground="White" HorizontalAlignment="Center" VerticalAlignment="Center"/>
                </Border>

                <StackPanel Grid.Column="1" VerticalAlignment="Center">
                    <TextBlock Text="AutopilotDoctor" FontSize="18" FontWeight="Bold" Foreground="#F9FAFB"/>
                    <TextBlock Text="Windows Autopilot, Entra ID, Intune MDM, SSL &amp; 802.1X Diagnostic Engine" FontSize="12" Foreground="#9CA3AF" Margin="0,2,0,0"/>
                </StackPanel>

                <Border x:Name="AdminBadge" Grid.Column="2" Background="#1E293B" BorderBrush="#334155" BorderThickness="1" CornerRadius="6" Padding="10,5" VerticalAlignment="Center">
                    <TextBlock x:Name="AdminBadgeText" Text="Checking Admin..." FontSize="11" FontWeight="SemiBold" Foreground="#93C5FD"/>
                </Border>
            </Grid>
        </Border>

        <!-- License Bar -->
        <Border Grid.Row="1" Background="#111827" BorderBrush="#283548" BorderThickness="1" CornerRadius="10" Padding="14" Margin="0,0,0,14">
            <Grid>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>

                <Grid Grid.Row="0">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                        <TextBlock Text="EDITION: " FontSize="11" FontWeight="Bold" Foreground="#6B7280"/>
                        <TextBlock x:Name="LicenseStatusLabel" Text="Free Edition" FontSize="12" FontWeight="Bold" Foreground="#FBBF24"/>
                    </StackPanel>
                    <Button x:Name="GetProBtn" Grid.Column="1" Content="Get Pro License ($39)" FontSize="11" Padding="10,4" Background="#1E3A8A" BorderBrush="#3B82F6"/>
                </Grid>

                <Grid x:Name="ActivationRow" Grid.Row="1" Margin="0,10,0,0">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <TextBox x:Name="LicenseKeyBox" Grid.Column="0" Height="32" Padding="8,5" Background="#0B0F19" Foreground="#F3F4F6"
                             BorderBrush="#374151" BorderThickness="1" FontFamily="Consolas" FontSize="12" VerticalContentAlignment="Center"
                             ToolTip="Paste your AutopilotDoctor Pro or MSP license key here"/>
                    <Button x:Name="ActivateBtn" Grid.Column="1" Content="Activate Key" Margin="8,0,0,0" Padding="14,5" FontSize="12"/>
                </Grid>
            </Grid>
        </Border>

        <!-- Diagnostic Options & Live Console -->
        <Border Grid.Row="2" Background="#111827" BorderBrush="#283548" BorderThickness="1" CornerRadius="10" Padding="16" Margin="0,0,0,14">
            <Grid>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="*"/>
                </Grid.RowDefinitions>

                <TextBlock Grid.Row="0" Text="DIAGNOSTIC SCAN CONFIGURATION" FontSize="11" FontWeight="Bold" Foreground="#6B7280" Margin="0,0,0,10"/>

                <StackPanel Grid.Row="1" Margin="0,0,0,12">
                    <CheckBox x:Name="AnonymizeCheck" Content="Anonymize Sensitive Identifiers (Mask Tenant ID, Hostname, UPN, SSID &amp; App Names for safe sharing)"
                              Foreground="#E5E7EB" FontSize="12" Margin="0,0,0,8" IsChecked="False"/>
                    <CheckBox x:Name="OpenReportCheck" Content="Automatically open interactive HTML Dashboard report in browser when scan finishes"
                              Foreground="#E5E7EB" FontSize="12" IsChecked="True"/>
                </StackPanel>

                <Border Grid.Row="2" Background="#0B0F19" BorderBrush="#1F2937" BorderThickness="1" CornerRadius="6" Padding="10">
                    <TextBox x:Name="StatusLogBox" Background="Transparent" Foreground="#34D399" BorderThickness="0"
                             FontFamily="Consolas" FontSize="11.5" IsReadOnly="True" TextWrapping="Wrap"
                             VerticalScrollBarVisibility="Auto"
                             Text="Ready. Click 'Run Full Diagnostic Scan' to inspect Modules A through E (Zero telemetry, 100% offline local analysis)."/>
                </Border>
            </Grid>
        </Border>

        <!-- Progress Bar -->
        <ProgressBar x:Name="ScanProgress" Grid.Row="3" Height="6" Background="#1F2937" Foreground="#3B82F6" BorderThickness="0" Margin="0,0,0,14" Value="0"/>

        <!-- Action Buttons -->
        <Grid Grid.Row="4">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
            </Grid.ColumnDefinitions>

            <Button x:Name="OpenFolderBtn" Grid.Column="0" Content="Open Reports Folder" FontSize="12"/>
            <Button x:Name="RunScanBtn" Grid.Column="2" Content="Run Full Diagnostic Scan" FontSize="13" Padding="22,10"
                    Background="#2563EB" BorderBrush="#3B82F6" Foreground="White"/>
        </Grid>
    </Grid>
</Window>
'@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$window = [Windows.Markup.XamlReader]::Load($reader)

# Bind UI Controls
$adminBadge      = $window.FindName("AdminBadge")
$adminBadgeText  = $window.FindName("AdminBadgeText")
$licStatusLabel  = $window.FindName("LicenseStatusLabel")
$getProBtn       = $window.FindName("GetProBtn")
$activationRow   = $window.FindName("ActivationRow")
$licenseKeyBox   = $window.FindName("LicenseKeyBox")
$activateBtn     = $window.FindName("ActivateBtn")
$anonymizeCheck  = $window.FindName("AnonymizeCheck")
$openReportCheck = $window.FindName("OpenReportCheck")
$statusLogBox    = $window.FindName("StatusLogBox")
$scanProgress    = $window.FindName("ScanProgress")
$openFolderBtn   = $window.FindName("OpenFolderBtn")
$runScanBtn      = $window.FindName("RunScanBtn")

# Check Elevation Status
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    $adminBadgeText.Text = "ADMIN ELEVATED"
    $adminBadgeText.Foreground = "#34D399"
    $adminBadge.BorderBrush = "#059669"
} else {
    $adminBadgeText.Text = "STANDARD USER (LIMITED)"
    $adminBadgeText.Foreground = "#FBBF24"
    $adminBadge.BorderBrush = "#D97706"
}

function Update-LicenseUi {
    $state = Get-LicenseStatus
    $script:CurrentLicense = $state
    $licStatusLabel.Text = $state.StatusText
    if ($state.IsPro) {
        $licStatusLabel.Foreground = "#34D399"
        $activationRow.Visibility = "Collapsed"
        $getProBtn.Visibility = "Collapsed"
    } else {
        $licStatusLabel.Foreground = "#FBBF24"
        $activationRow.Visibility = "Visible"
        $getProBtn.Visibility = "Visible"
    }
}

Update-LicenseUi

# Button Events
$getProBtn.Add_Click({
    Start-Process $script:CheckoutUrl
})

$activateBtn.Add_Click({
    $activateBtn.IsEnabled = $false
    $activateBtn.Content = "Validating..."
    $res = Invoke-LicenseActivation -KeyInput $licenseKeyBox.Text
    $activateBtn.IsEnabled = $true
    $activateBtn.Content = "Activate Key"

    if ($res.Success) {
        [System.Windows.MessageBox]::Show($res.Message, "AutopilotDoctor License", "OK", "Information") | Out-Null
        Update-LicenseUi
    } else {
        [System.Windows.MessageBox]::Show($res.Message, "License Activation", "OK", "Warning") | Out-Null
    }
})

$openFolderBtn.Add_Click({
    if (-not (Test-Path $script:ReportDir)) {
        New-Item -ItemType Directory -Path $script:ReportDir -Force | Out-Null
    }
    Start-Process $script:ReportDir
})

# Background Diagnostic Execution via Runspace (Keeps UI Responsive)
$script:ActivePowerShell = $null
$script:AsyncHandle      = $null
$script:Timer            = New-Object System.Windows.Threading.DispatcherTimer
$script:Timer.Interval   = [TimeSpan]::FromMilliseconds(350)

$script:Timer.Add_Tick({
    if ($null -ne $script:AsyncHandle -and $script:AsyncHandle.IsCompleted) {
        $script:Timer.Stop()
        $scanProgress.IsIndeterminate = $false
        $scanProgress.Value = 100

        try {
            $result = $script:ActivePowerShell.EndInvoke($script:AsyncHandle)
            $reportInfo = $result | Where-Object { $_ -is [PSCustomObject] -and $_.PSObject.Properties['HtmlPath'] } | Select-Object -Last 1

            $statusLogBox.AppendText("`r`n[OK] Scan complete! Health: $($reportInfo.OverallHealth) (Critical: $($reportInfo.Critical), Warning: $($reportInfo.Warning), Pass: $($reportInfo.Pass))")
            $statusLogBox.AppendText("`r`n[OK] Report saved to: $($reportInfo.HtmlPath)")
            $statusLogBox.ScrollToEnd()

            if ($openReportCheck.IsChecked -and (Test-Path $reportInfo.HtmlPath)) {
                Start-Process $reportInfo.HtmlPath
            }
        } catch {
            $statusLogBox.AppendText("`r`n[ERROR] Diagnostic scan failed: $($_.Exception.Message)")
            $statusLogBox.ScrollToEnd()
        } finally {
            if ($script:ActivePowerShell) { $script:ActivePowerShell.Dispose() }
            $script:ActivePowerShell = $null
            $script:AsyncHandle = $null
            $runScanBtn.IsEnabled = $true
            $runScanBtn.Content = "Run Full Diagnostic Scan"
        }
    }
})

$runScanBtn.Add_Click({
    $runScanBtn.IsEnabled = $false
    $runScanBtn.Content = "Scanning Modules A-E..."
    $scanProgress.IsIndeterminate = $true

    if (-not (Test-Path $script:ReportDir)) {
        New-Item -ItemType Directory -Path $script:ReportDir -Force | Out-Null
    }

    $timestamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $jsonOut   = Join-Path $script:ReportDir "AutopilotDoctor-$timestamp.json"
    $htmlOut   = Join-Path $script:ReportDir "AutopilotDoctor-$timestamp.html"
    $useAnon   = [bool]$anonymizeCheck.IsChecked
    $isPro     = [bool]$script:CurrentLicense.IsPro
    $devDir    = $PSScriptRoot

    $statusLogBox.Text = "[*] Initializing diagnostic runspace...`r`n[*] Probing Entra ID, TPM 2.0, Intune MDM, TCP 443 endpoints, TLS chains, Certificates, 802.1X & BitLocker..."

    $ps = [PowerShell]::Create()
    $null = $ps.AddScript({
        param($CoreB64, $HtmlB64, $DevRoot, $JsonPath, $HtmlPath, $AnonymizeFlag, $IsProLicensed)

        $tempWorkDir = Join-Path $env:TEMP ("APD_" + [Guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Path $tempWorkDir -Force | Out-Null

        try {
            # Resolve scripts from embedded Base64 (compiled .exe) or local src folder (dev mode)
            if ($CoreB64 -notmatch '^__EMBEDDED_') {
                $coreScriptPath = Join-Path $tempWorkDir "Core.ps1"
                [System.IO.File]::WriteAllBytes($coreScriptPath, [Convert]::FromBase64String($CoreB64))
            } else {
                $coreScriptPath = Join-Path $DevRoot "AutopilotDoctor-CoreABCDE.ps1"
            }

            if ($HtmlB64 -notmatch '^__EMBEDDED_') {
                $htmlScriptPath = Join-Path $tempWorkDir "Html.ps1"
                [System.IO.File]::WriteAllBytes($htmlScriptPath, [Convert]::FromBase64String($HtmlB64))
            } else {
                $htmlScriptPath = Join-Path $DevRoot "New-AutopilotHtmlReport.ps1"
            }

            # Execute Core Diagnostic Engine
            $null = & $coreScriptPath -Anonymize:$AnonymizeFlag -OutputPath $JsonPath

            # Apply Freemium Feature Gate if Free Edition
            $payloadObj = Get-Content -Path $JsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if (-not $IsProLicensed -and $payloadObj.PSObject.Properties['findings']) {
                foreach ($f in $payloadObj.findings) {
                    if ($f.PSObject.Properties['remediationHint'] -and $f.remediationHint -and $f.remediationHint -ne "None") {
                        $f.remediationHint = "[PRO LICENSE REQUIRED] Upgrade to AutopilotDoctor Pro to unlock copy-paste remediation commands & CLI fixes."
                    }
                }
                ($payloadObj | ConvertTo-Json -Depth 6) | Out-File -FilePath $JsonPath -Encoding UTF8 -Force
            }

            # Generate Standalone HTML Report
            & $htmlScriptPath -JsonPath $JsonPath -HtmlOutputPath $HtmlPath

            # Remove raw JSON file in Free Edition (JSON export is a Pro feature)
            if (-not $IsProLicensed -and (Test-Path $JsonPath)) {
                Remove-Item -Path $JsonPath -Force -ErrorAction SilentlyContinue
            }

            return [PSCustomObject]@{
                HtmlPath      = $HtmlPath
                OverallHealth = $payloadObj.summary.overallHealth
                Critical      = $payloadObj.summary.criticalCount
                Warning       = $payloadObj.summary.warningCount
                Pass          = $payloadObj.summary.passCount
            }
        } finally {
            if (Test-Path $tempWorkDir) {
                Remove-Item -Path $tempWorkDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }).AddArgument($script:EmbeddedCoreBase64).AddArgument($script:EmbeddedHtmlBase64).AddArgument($devDir).AddArgument($jsonOut).AddArgument($htmlOut).AddArgument($useAnon).AddArgument($isPro)

    $script:ActivePowerShell = $ps
    $script:AsyncHandle = $ps.BeginInvoke()
    $script:Timer.Start()
})

$null = $window.ShowDialog()