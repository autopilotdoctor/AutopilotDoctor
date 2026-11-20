<#
.SYNOPSIS
    AutopilotDoctor Core Engine - Modules A, B, C, D & E
.DESCRIPTION
    Collects, normalizes, and evaluates Windows Entra ID join states, TPM 2.0 health, Intune MDM enrollment,
    sync cadence, Event Viewer diagnostics, TCP 443 endpoint reachability, TLS/SSL inspection,
    LocalMachine/CurrentUser certificates, Enterprise 802.1X Wi-Fi health, Win32 App IME logs, and BitLocker/Storage.
    100% compatible with PowerShell 5.1+ and Set-StrictMode -Version Latest with zero external dependencies.
.PARAMETER Anonymize
    Masks sensitive tenant, device, hostname, SSID, CA, app name, and user identifiers for safe external sharing.
.PARAMETER OutputPath
    Optional file path to export the resulting JSON payload.
#>

[CmdletBinding()]
param (
    [switch]$Anonymize,
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

#region Helper Functions

function Protect-SensitiveString {
    param (
        [string]$Value,
        [string]$Prefix = "MASKED"
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    if (-not $Anonymize) { return $Value }

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        $hashBytes = $sha.ComputeHash($bytes)
        $shortHash = [BitConverter]::ToString($hashBytes).Replace("-", "").Substring(0, 8)
        return "$Prefix-$shortHash"
    } finally {
        $sha.Dispose()
    }
}

function Get-SafePropertyValue {
    param (
        [object]$InputObject,
        [string]$PropertyName,
        $DefaultValue = $null
    )
    if ($null -eq $InputObject) { return $DefaultValue }
    if ($InputObject.PSObject.Properties[$PropertyName]) {
        return $InputObject.$PropertyName
    }
    return $DefaultValue
}

function Add-Finding {
    param (
        [System.Collections.Generic.List[object]]$FindingsList,
        [string]$Module,
        [string]$CheckId,
        [string]$Title,
        [ValidateSet('Pass', 'Warning', 'Critical', 'Info')]
        [string]$Severity,
        [string]$ObservedValue,
        [string]$Summary,
        [string]$RemediationHint
    )

    $FindingsList.Add([PSCustomObject]@{
        module          = $Module
        checkId         = $CheckId
        title           = $Title
        severity        = $Severity
        observedValue   = $ObservedValue
        summary         = $Summary
        remediationHint = $RemediationHint
    })
}

#endregion

#region Module A: Identity, Entra ID & Hardware Readiness

function Get-ModuleAIdentityData {
    param (
        [System.Collections.Generic.List[object]]$Findings
    )

    $dsregRaw = & dsregcmd.exe /status 2>&1
    $dsregMap = @{}

    if ($dsregRaw) {
        foreach ($line in $dsregRaw) {
            if ($line -match '^\s*([^:]+?)\s*:\s*(.+?)\s*$') {
                $key = $matches[1].Trim()
                $val = $matches[2].Trim()
                if (-not $dsregMap.ContainsKey($key)) {
                    $dsregMap[$key] = $val
                }
            }
        }
    }

    $azureAdJoined      = $dsregMap['AzureAdJoined']
    $enterpriseJoined   = $dsregMap['EnterpriseJoined']
    $domainJoined       = $dsregMap['DomainJoined']
    $deviceId           = $dsregMap['DeviceId']
    $tenantId           = $dsregMap['TenantId']
    $tenantName         = $dsregMap['TenantName']
    $mdmUrl             = $dsregMap['MdmUrl']
    $aadRecoveryEnabled = $dsregMap['AadRecoveryEnabled']
    $keySignTest        = $dsregMap['KeySignTest']
    $azureAdPrt         = $dsregMap['AzureAdPrt']
    $azureAdPrtUpdate   = $dsregMap['AzureAdPrtUpdateTime']
    $ngcSet             = $dsregMap['NgcSet']

    $joinType = "Workgroup / Unjoined"
    if ($azureAdJoined -eq 'YES' -and $domainJoined -eq 'YES') {
        $joinType = "Hybrid Entra ID Joined"
    } elseif ($azureAdJoined -eq 'YES') {
        $joinType = "Entra ID Joined"
    } elseif ($domainJoined -eq 'YES') {
        $joinType = "On-Premises AD Joined Only"
    }

    if ($azureAdJoined -eq 'YES') {
        Add-Finding -FindingsList $Findings -Module "ModuleA" -CheckId "ENTRA-JOIN-01" `
            -Title "Entra ID Device Registration" -Severity "Pass" -ObservedValue $joinType `
            -Summary "Device is properly joined ($joinType)." -RemediationHint "None"
    } else {
        Add-Finding -FindingsList $Findings -Module "ModuleA" -CheckId "ENTRA-JOIN-01" `
            -Title "Entra ID Device Registration" -Severity "Critical" -ObservedValue $joinType `
            -Summary "Device is NOT joined to Entra ID. Intune policies and cloud authentication will fail." `
            -RemediationHint "Verify Autopilot profile assignment or run 'dsregcmd /debug /leave' followed by re-enrollment."
    }

    if ($aadRecoveryEnabled -eq 'YES') {
        Add-Finding -FindingsList $Findings -Module "ModuleA" -CheckId "ENTRA-REC-02" `
            -Title "Entra ID Device Recovery State" -Severity "Critical" -ObservedValue "YES" `
            -Summary "AadRecoveryEnabled is YES. Device keys are out of sync with Entra ID, causing authentication/PIN loops." `
            -RemediationHint "Have user sign in via Settings > Accounts > Access work or school to re-authenticate, or run dsregcmd /forcerecovery."
    }

    if ($azureAdJoined -eq 'YES') {
        if ($keySignTest -eq 'PASSED') {
            Add-Finding -FindingsList $Findings -Module "ModuleA" -CheckId "ENTRA-KEY-03" `
                -Title "Cryptographic Key Sign Test" -Severity "Pass" -ObservedValue $keySignTest `
                -Summary "Device transport key is healthy." -RemediationHint "None"
        } else {
            $observedKeySign = if ([string]::IsNullOrWhiteSpace($keySignTest)) { "UNKNOWN" } else { $keySignTest }
            Add-Finding -FindingsList $Findings -Module "ModuleA" -CheckId "ENTRA-KEY-03" `
                -Title "Cryptographic Key Sign Test" -Severity "Critical" -ObservedValue $observedKeySign `
                -Summary "KeySignTest failed. Hardware TPM or NGC key corruption detected." `
                -RemediationHint "Check TPM health and clear NGC folder if Windows Hello for Business fails."
        }

        if ($azureAdPrt -eq 'YES') {
            Add-Finding -FindingsList $Findings -Module "ModuleA" -CheckId "ENTRA-PRT-04" `
                -Title "Primary Refresh Token (PRT)" -Severity "Pass" -ObservedValue "YES ($azureAdPrtUpdate)" `
                -Summary "Active SSO token present for cloud resources." -RemediationHint "None"
        } elseif ($azureAdPrt -eq 'NO') {
            Add-Finding -FindingsList $Findings -Module "ModuleA" -CheckId "ENTRA-PRT-04" `
                -Title "Primary Refresh Token (PRT)" -Severity "Warning" -ObservedValue "NO" `
                -Summary "No active PRT in current session (normal during OOBE/SYSTEM context, problematic in active user session)." `
                -RemediationHint "Ensure user logged in with Entra ID credentials rather than a local account."
        }
    }

    $tpmInfo = $null
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        $tpmCim = Get-CimInstance -Namespace "root\cimv2\security\microsofttpm" -ClassName Win32_Tpm -ErrorAction SilentlyContinue
        $tpmSpec = Get-SafePropertyValue -InputObject $tpmCim -PropertyName "SpecVersion"
        $specClean = if ($tpmSpec) { ($tpmSpec -split ',')[0].Trim() } else { "Unknown" }

        $tpmInfo = [PSCustomObject]@{
            present     = [bool]$tpm.TpmPresent
            ready       = [bool]$tpm.TpmReady
            enabled     = [bool]$tpm.TpmEnabled
            activated   = [bool]$tpm.TpmActivated
            owned       = [bool]$tpm.TpmOwned
            specVersion = $specClean
        }

        if ($tpm.TpmPresent -and $tpm.TpmReady -and $specClean -like "2.*") {
            Add-Finding -FindingsList $Findings -Module "ModuleA" -CheckId "HW-TPM-01" `
                -Title "TPM 2.0 Hardware Readiness" -Severity "Pass" -ObservedValue "Ready (Spec $specClean)" `
                -Summary "TPM 2.0 is present, enabled, and ready for Autopilot attestation and BitLocker." -RemediationHint "None"
        } else {
            Add-Finding -FindingsList $Findings -Module "ModuleA" -CheckId "HW-TPM-01" `
                -Title "TPM 2.0 Hardware Readiness" -Severity "Critical" -ObservedValue "Present:$($tpm.TpmPresent) Ready:$($tpm.TpmReady) Spec:$specClean" `
                -Summary "TPM 2.0 is missing, disabled in BIOS, or not ready. Autopilot self-deploy/pre-provisioning will fail." `
                -RemediationHint "Enable TPM 2.0 / PTT / fTPM in UEFI/BIOS settings and clear TPM if necessary."
        }
    } catch {
        $tpmInfo = [PSCustomObject]@{ error = "Unable to query TPM (Requires Admin privileges)" }
        Add-Finding -FindingsList $Findings -Module "ModuleA" -CheckId "HW-TPM-01" `
            -Title "TPM 2.0 Hardware Readiness" -Severity "Warning" -ObservedValue "Access Denied" `
            -Summary "Could not read TPM status. Tool may not be running with elevated administrator privileges." `
            -RemediationHint "Re-run AutopilotDoctor as Administrator."
    }

    return [PSCustomObject]@{
        joinType           = $joinType
        azureAdJoined      = $azureAdJoined
        enterpriseJoined   = $enterpriseJoined
        domainJoined       = $domainJoined
        deviceId           = Protect-SensitiveString -Value $deviceId -Prefix "DEV"
        tenantId           = Protect-SensitiveString -Value $tenantId -Prefix "TENANT"
        tenantName         = Protect-SensitiveString -Value $tenantName -Prefix "ORG"
        mdmDiscoveryUrl    = $mdmUrl
        aadRecoveryEnabled = $aadRecoveryEnabled
        keySignTest        = $keySignTest
        azureAdPrt         = $azureAdPrt
        azureAdPrtUpdated  = $azureAdPrtUpdate
        windowsHelloSet    = $ngcSet
        tpm                = $tpmInfo
    }
}

#endregion

#region Module B: Intune MDM Enrollment, Sync & Event Diagnostics

function Get-ModuleBIntuneMdmData {
    param (
        [System.Collections.Generic.List[object]]$Findings
    )

    $enrollmentsBase = "HKLM:\SOFTWARE\Microsoft\Enrollments"
    $mdmEnrollment = $null

    if (Test-Path $enrollmentsBase) {
        $subKeys = Get-ChildItem -Path $enrollmentsBase
        foreach ($key in $subKeys) {
            $props = Get-ItemProperty -Path $key.PSPath
            $providerId = Get-SafePropertyValue -InputObject $props -PropertyName "ProviderID"
            if ($providerId -eq 'MS DM Server') {
                $guid = $key.PSChildName
                $upn = Get-SafePropertyValue -InputObject $props -PropertyName "UPN" -DefaultValue "Unknown"
                $discoveryUrl = Get-SafePropertyValue -InputObject $props -PropertyName "DiscoveryServiceFullURL"
                $enrollmentState = Get-SafePropertyValue -InputObject $props -PropertyName "EnrollmentState" -DefaultValue -1

                $pollPath = Join-Path $key.PSPath "Poll"
                $lastSyncTimeUtc = $null
                $hoursSinceLastSync = $null

                if (Test-Path $pollPath) {
                    $pollProps = Get-ItemProperty -Path $pollPath
                    $rawSyncTime = Get-SafePropertyValue -InputObject $pollProps -PropertyName "LastSuccessfulSyncTime"
                    if ($rawSyncTime) {
                        try {
                            if ($rawSyncTime -is [int64] -or $rawSyncTime -is [int32]) {
                                $dt = [DateTime]::FromFileTimeUtc([int64]$rawSyncTime)
                            } else {
                                $dt = [DateTime]::Parse($rawSyncTime).ToUniversalTime()
                            }
                            $lastSyncTimeUtc = $dt.ToString("yyyy-MM-ddTHH:mm:ssZ")
                            $hoursSinceLastSync = [math]::Round(((Get-Date).ToUniversalTime() - $dt).TotalHours, 1)
                        } catch {
                            $lastSyncTimeUtc = "ParseError"
                        }
                    }
                }

                $syncTasks = Get-ScheduledTask -TaskPath "\Microsoft\Windows\EnterpriseMgmt\$guid\" -ErrorAction SilentlyContinue
                $taskCount = if ($syncTasks) { @($syncTasks).Count } else { 0 }

                $mdmEnrollment = [PSCustomObject]@{
                    enrollmentGuid     = Protect-SensitiveString -Value $guid -Prefix "MDM"
                    providerId         = $providerId
                    enrolledUpn        = Protect-SensitiveString -Value $upn -Prefix "USER"
                    enrollmentState    = $enrollmentState
                    discoveryUrl       = $discoveryUrl
                    lastSyncUtc        = $lastSyncTimeUtc
                    hoursSinceLastSync = $hoursSinceLastSync
                    scheduledTaskCount = $taskCount
                }
            }
        }
    }

    if ($null -eq $mdmEnrollment) {
        Add-Finding -FindingsList $Findings -Module "ModuleB" -CheckId "MDM-ENROLL-01" `
            -Title "Intune MDM Enrollment Presence" -Severity "Critical" -ObservedValue "Not Enrolled" `
            -Summary "No active 'MS DM Server' MDM enrollment found in registry." `
            -RemediationHint "Check user M365 Intune license, MDM user scope in Entra ID, or trigger auto-enrollment via 'deviceenroller.exe /c /AutoEnrollMDM'."
    } else {
        Add-Finding -FindingsList $Findings -Module "ModuleB" -CheckId "MDM-ENROLL-01" `
            -Title "Intune MDM Enrollment Presence" -Severity "Pass" -ObservedValue "Enrolled (State: $($mdmEnrollment.enrollmentState))" `
            -Summary "Active Intune MDM enrollment record verified." -RemediationHint "None"

        if ($mdmEnrollment.scheduledTaskCount -eq 0) {
            Add-Finding -FindingsList $Findings -Module "ModuleB" -CheckId "MDM-TASK-02" `
                -Title "EnterpriseMgmt Scheduled Tasks" -Severity "Critical" -ObservedValue "0 Tasks" `
                -Summary "MDM sync scheduled tasks are missing. Device will never check in automatically." `
                -RemediationHint "Re-register MDM scheduled tasks or re-enroll device."
        }

        if ($null -ne $mdmEnrollment.hoursSinceLastSync) {
            if ($mdmEnrollment.hoursSinceLastSync -gt 168) {
                Add-Finding -FindingsList $Findings -Module "ModuleB" -CheckId "MDM-SYNC-03" `
                    -Title "Last Successful Intune Policy Sync" -Severity "Critical" -ObservedValue "$($mdmEnrollment.hoursSinceLastSync) hours ago" `
                    -Summary "Device has not synced with Intune for over 7 days." `
                    -RemediationHint "Check firewall/proxy access to *.manage.microsoft.com and restart 'dmwappushservice' service."
            } elseif ($mdmEnrollment.hoursSinceLastSync -gt 24) {
                Add-Finding -FindingsList $Findings -Module "ModuleB" -CheckId "MDM-SYNC-03" `
                    -Title "Last Successful Intune Policy Sync" -Severity "Warning" -ObservedValue "$($mdmEnrollment.hoursSinceLastSync) hours ago" `
                    -Summary "Device sync is delayed (>24 hours)." `
                    -RemediationHint "Trigger manual sync from Settings > Accounts > Access work or school > Info > Sync."
            } else {
                Add-Finding -FindingsList $Findings -Module "ModuleB" -CheckId "MDM-SYNC-03" `
                    -Title "Last Successful Intune Policy Sync" -Severity "Pass" -ObservedValue "$($mdmEnrollment.hoursSinceLastSync) hours ago" `
                    -Summary "Intune sync cadence is healthy." -RemediationHint "None"
            }
        }
    }

    $imeService = Get-Service -Name "IntuneManagementExtension" -ErrorAction SilentlyContinue
    $imeStatus = if ($imeService) { $imeService.Status.ToString() } else { "NotInstalled" }

    if ($imeStatus -eq "Running") {
        Add-Finding -FindingsList $Findings -Module "ModuleB" -CheckId "MDM-IME-04" `
            -Title "Intune Management Extension (IME)" -Severity "Pass" -ObservedValue "Running" `
            -Summary "IME agent is running (Win32 apps & PowerShell scripts supported)." -RemediationHint "None"
    } elseif ($imeStatus -eq "NotInstalled") {
        Add-Finding -FindingsList $Findings -Module "ModuleB" -CheckId "MDM-IME-04" `
            -Title "Intune Management Extension (IME)" -Severity "Info" -ObservedValue "Not Installed" `
            -Summary "IME agent not installed yet (normal if no Win32 apps or scripts are assigned)." -RemediationHint "None"
    } else {
        Add-Finding -FindingsList $Findings -Module "ModuleB" -CheckId "MDM-IME-04" `
            -Title "Intune Management Extension (IME)" -Severity "Critical" -ObservedValue $imeStatus `
            -Summary "IME service is installed but not running. Win32 apps and remediations are stalled." `
            -RemediationHint "Start 'IntuneManagementExtension' service and inspect IntuneManagementExtension.log."
    }

    $knownErrorKB = @{
        "0x80180014" = "MDM enrollment disabled by tenant policy or user lacks Intune license."
        "0x80180026" = "Device is already enrolled or stale enrollment registry keys exist."
        "0x8018002b" = "MDM Discovery URL failed or network blocked during enrollment."
        "0x80072ee7" = "DNS resolution failure reaching Intune endpoints (check DNS/Proxy)."
        "0x80072efd" = "TCP connection to Intune endpoint refused or blocked by firewall."
        "0x80190190" = "HTTP 400 Bad Request - often caused by system clock skew (>5 mins) or corrupted device cert."
        "0x80190191" = "HTTP 401 Unauthorized - device certificate expired or user token invalid."
        "0x80190193" = "HTTP 403 Forbidden - Conditional Access or enrollment restriction blocking device."
        "0x82aa0008" = "CSP policy application error or invalid OMA-URI configuration."
    }

    $recentErrors = @()
    $startTime = (Get-Date).AddHours(-72)
    $logName = "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin"

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = $logName
            Level     = @(1, 2)
            StartTime = $startTime
        } -MaxEvents 25 -ErrorAction Stop

        foreach ($ev in $events) {
            $msg = $ev.Message
            $hexCode = $null
            if ($msg -match '(0x[0-9a-fA-F]{8})') {
                $hexCode = $matches[1].ToLower()
            }

            $humanExplanation = if ($hexCode -and $knownErrorKB.ContainsKey($hexCode)) {
                $knownErrorKB[$hexCode]
            } else {
                "Unmapped MDM diagnostic error. Review raw event message for OMA-URI or CSP details."
            }

            $recentErrors += [PSCustomObject]@{
                timeUtc          = $ev.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                eventId          = $ev.Id
                hexErrorCode     = $hexCode
                humanExplanation = $humanExplanation
                rawMessage       = if ($msg.Length -gt 350) { $msg.Substring(0, 350) + "..." } else { $msg }
            }
        }
    } catch {
        # No events found or log inaccessible
    }

    if ($recentErrors.Count -gt 0) {
        $uniqueCodes = ($recentErrors | Where-Object { $_.hexErrorCode } | Select-Object -ExpandProperty hexErrorCode -Unique) -join ", "
        Add-Finding -FindingsList $Findings -Module "ModuleB" -CheckId "MDM-EVT-05" `
            -Title "MDM Diagnostic Event Log Errors (72h)" -Severity "Warning" -ObservedValue "$($recentErrors.Count) errors ($uniqueCodes)" `
            -Summary "Detected recent MDM policy or sync failures in Event Viewer." `
            -RemediationHint "Inspect mapped error codes in the Event Diagnostics table below."
    } else {
        Add-Finding -FindingsList $Findings -Module "ModuleB" -CheckId "MDM-EVT-05" `
            -Title "MDM Diagnostic Event Log Errors (72h)" -Severity "Pass" -ObservedValue "0 Errors" `
            -Summary "No critical MDM diagnostic errors logged in the past 72 hours." -RemediationHint "None"
    }

    return [PSCustomObject]@{
        isMdmEnrolled      = ($null -ne $mdmEnrollment)
        primaryEnrollment  = $mdmEnrollment
        imeServiceStatus   = $imeStatus
        recentMdmErrors72h = $recentErrors
    }
}

#endregion

#region Module C: Network, Firewall Endpoints & SSL Inspection Diagnostics

function Test-EndpointTlsAndPort {
    param (
        [string]$Hostname,
        [string]$Category,
        [int]$Port = 443,
        [int]$TimeoutMs = 2000,
        [bool]$InspectCertificate = $false
    )

    $tcpReachable = $false
    $latencyMs = $null
    $tlsIssuer = $null
    $sslInspectionDetected = $false
    $errorDetail = $null

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $waitHandle = $null
    $sslStream = $null

    try {
        $asyncResult = $tcpClient.BeginConnect($Hostname, $Port, $null, $null)
        $waitHandle = $asyncResult.AsyncWaitHandle
        $connected = $waitHandle.WaitOne($TimeoutMs, $false)

        if ($connected -and $tcpClient.Connected) {
            $tcpClient.EndConnect($asyncResult)
            $tcpReachable = $true
            $latencyMs = $sw.ElapsedMilliseconds

            if ($InspectCertificate) {
                try {
                    $certCallback = { param($callbackSender, $certificate, $chain, $sslPolicyErrors) return $true }
                    $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, $certCallback)
                    $sslStream.AuthenticateAsClient($Hostname)

                    if ($sslStream.RemoteCertificate) {
                        $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($sslStream.RemoteCertificate)
                        $tlsIssuer = $cert2.Issuer

                        $trustedIssuersPattern = '(Microsoft|DigiCert|Baltimore|GlobalSign|Sectigo|Entrust|CyberTrust)'
                        if ($tlsIssuer -notmatch $trustedIssuersPattern) {
                            $sslInspectionDetected = $true
                        }
                    }
                } catch {
                    $innerMsg = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
                    $errorDetail = "TLS Handshake Error: $innerMsg"
                }
            }
        } else {
            $errorDetail = "Connection timed out after ${TimeoutMs}ms (Blocked by Firewall/Proxy or DNS failure)"
        }
    } catch {
        $errorDetail = $_.Exception.Message
    } finally {
        $sw.Stop()
        if ($sslStream) { $sslStream.Dispose() }
        if ($waitHandle) { $waitHandle.Close() }
        if ($tcpClient) { $tcpClient.Close(); $tcpClient.Dispose() }
    }

    return [PSCustomObject]@{
        hostname              = $Hostname
        category              = $Category
        port                  = $Port
        tcpReachable          = $tcpReachable
        latencyMs             = $latencyMs
        tlsIssuer             = $tlsIssuer
        sslInspectionDetected = $sslInspectionDetected
        errorDetail           = $errorDetail
    }
}

function Get-ModuleCNetworkData {
    param (
        [System.Collections.Generic.List[object]]$Findings
    )

    $inetSettings = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
    $proxyEnableVal   = Get-SafePropertyValue -InputObject $inetSettings -PropertyName "ProxyEnable" -DefaultValue 0
    $userProxyEnabled = [bool]($proxyEnableVal -eq 1)
    $userProxyServer  = Get-SafePropertyValue -InputObject $inetSettings -PropertyName "ProxyServer"
    $userPacUrl       = Get-SafePropertyValue -InputObject $inetSettings -PropertyName "AutoConfigURL"

    $winHttpRaw = & netsh.exe winhttp show proxy 2>&1 | Out-String
    $winHttpDirect = ($winHttpRaw -match 'Direct access \(no proxy server\)')
    $winHttpProxyServer = $null
    if (-not $winHttpDirect -and $winHttpRaw -match 'Proxy Server\(s\)\s*:\s*(.+)') {
        $winHttpProxyServer = $matches[1].Trim()
    }

    if (($userProxyEnabled -or $userPacUrl) -and $winHttpDirect) {
        Add-Finding -FindingsList $Findings -Module "ModuleC" -CheckId "NET-PROXY-01" `
            -Title "WinHTTP vs. User Proxy Mismatch" -Severity "Warning" `
            -ObservedValue "User Proxy: Active | WinHTTP: Direct" `
            -Summary "User session uses a proxy/PAC file, but SYSTEM WinHTTP is set to Direct Access. Autopilot OOBE and IME services run as SYSTEM and may fail to reach Microsoft endpoints." `
            -RemediationHint "Import user proxy settings to WinHTTP via 'netsh winhttp import proxy source=ie' or configure WPAD/transparent proxy."
    } else {
        $proxyObs = if ($winHttpDirect) { "Direct Access" } else { "WinHTTP Proxy Configured" }
        Add-Finding -FindingsList $Findings -Module "ModuleC" -CheckId "NET-PROXY-01" `
            -Title "System Proxy Alignment" -Severity "Pass" `
            -ObservedValue $proxyObs `
            -Summary "No conflicting User vs. SYSTEM proxy mismatch detected." -RemediationHint "None"
    }

    $endpointsToTest = @(
        @{ Host = "login.microsoftonline.com";          Cat = "Entra ID Auth";       Inspect = $true  }
        @{ Host = "device.login.microsoftonline.com";   Cat = "Entra Device Auth";   Inspect = $true  }
        @{ Host = "enterpriseregistration.windows.net"; Cat = "MDM Discovery";       Inspect = $true  }
        @{ Host = "enrollment.manage.microsoft.com";    Cat = "Intune Enrollment";   Inspect = $true  }
        @{ Host = "portal.manage.microsoft.com";        Cat = "Intune Management";   Inspect = $true  }
        @{ Host = "fef.msua01.manage.microsoft.com";    Cat = "Intune Scale Unit";   Inspect = $false }
        @{ Host = "ztd.dds.microsoft.com";              Cat = "Autopilot ZTD";       Inspect = $true  }
        @{ Host = "cs.dds.microsoft.com";               Cat = "Autopilot Config";    Inspect = $false }
        @{ Host = "EKCert.spserv.microsoft.com";        Cat = "TPM Attestation";     Inspect = $false }
        @{ Host = "ftpm.amd.com";                       Cat = "AMD TPM Attestation"; Inspect = $false }
        @{ Host = "go.microsoft.com";                   Cat = "Microsoft Redirects"; Inspect = $false }
        @{ Host = "www.msftconnecttest.com";            Cat = "NCSI Connectivity";   Inspect = $false }
    )

    $endpointResults = @()
    foreach ($ep in $endpointsToTest) {
        $endpointResults += Test-EndpointTlsAndPort -Hostname $ep.Host -Category $ep.Cat -InspectCertificate $ep.Inspect
    }

    $unreachableEndpoints = @($endpointResults | Where-Object { -not $_.tcpReachable })
    $inspectedEndpoints   = @($endpointResults | Where-Object { $_.sslInspectionDetected })

    if ($unreachableEndpoints.Count -gt 0) {
        $failedNames = ($unreachableEndpoints | Select-Object -ExpandProperty hostname) -join ", "
        Add-Finding -FindingsList $Findings -Module "ModuleC" -CheckId "NET-PORT-02" `
            -Title "Microsoft Cloud Endpoint Reachability (TCP 443)" -Severity "Critical" `
            -ObservedValue "$($unreachableEndpoints.Count)/$($endpointResults.Count) Blocked" `
            -Summary "Critical Microsoft endpoints are unreachable over TCP 443: $failedNames" `
            -RemediationHint "Whitelist Microsoft Intune & Autopilot FQDNs on TCP 443 in your perimeter firewall/proxy."
    } else {
        Add-Finding -FindingsList $Findings -Module "ModuleC" -CheckId "NET-PORT-02" `
            -Title "Microsoft Cloud Endpoint Reachability (TCP 443)" -Severity "Pass" `
            -ObservedValue "$($endpointResults.Count)/$($endpointResults.Count) Reachable" `
            -Summary "All tested Entra ID, Intune, and Autopilot endpoints are reachable on TCP 443." -RemediationHint "None"
    }

    if ($inspectedEndpoints.Count -gt 0) {
        $sampleIssuer = $inspectedEndpoints[0].tlsIssuer
        $affectedHosts = ($inspectedEndpoints | Select-Object -ExpandProperty hostname) -join ", "
        Add-Finding -FindingsList $Findings -Module "ModuleC" -CheckId "NET-SSL-03" `
            -Title "TLS / SSL Inspection Interception Detected" -Severity "Critical" `
            -ObservedValue "Intercepted ($($inspectedEndpoints.Count) endpoints)" `
            -Summary "Corporate proxy/firewall is decrypting HTTPS traffic for Microsoft endpoints ($affectedHosts). Issuer: $sampleIssuer. Microsoft Autopilot/Intune requires SSL bypass." `
            -RemediationHint "Add SSL/TLS decryption bypass rules on your firewall/proxy (Zscaler/Fortinet/Palo Alto) for *.manage.microsoft.com, *.microsoftonline.com, and *.dds.microsoft.com."
    } else {
        Add-Finding -FindingsList $Findings -Module "ModuleC" -CheckId "NET-SSL-03" `
            -Title "TLS / SSL Inspection Integrity" -Severity "Pass" `
            -ObservedValue "Clean Microsoft/Public CA Chain" `
            -Summary "No SSL/TLS man-in-the-middle proxy interception detected on tested Microsoft endpoints." -RemediationHint "None"
    }

    $ncsiProps = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" -ErrorAction SilentlyContinue
    $ncsiActiveProbe = Get-SafePropertyValue -InputObject $ncsiProps -PropertyName "EnableActiveProbing" -DefaultValue 1
    $ncsiStatus = if ($ncsiActiveProbe -eq 0) { "Disabled via Policy" } else { "Enabled" }

    if ($ncsiActiveProbe -eq 0) {
        Add-Finding -FindingsList $Findings -Module "ModuleC" -CheckId "NET-NCSI-04" `
            -Title "Windows NCSI Active Probing" -Severity "Warning" `
            -ObservedValue "Disabled (0)" `
            -Summary "EnableActiveProbing is set to 0. Windows may falsely report 'No Internet', causing Office 365 and Intune apps to stall." `
            -RemediationHint "Set HKLM:\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet\EnableActiveProbing to 1."
    }

    return [PSCustomObject]@{
        proxyConfiguration = [PSCustomObject]@{
            userProxyEnabled   = $userProxyEnabled
            userProxyServer    = $userProxyServer
            userPacUrl         = $userPacUrl
            winHttpDirect      = $winHttpDirect
            winHttpProxyServer = $winHttpProxyServer
        }
        ncsiActiveProbing = $ncsiStatus
        endpoints         = $endpointResults
    }
}

#endregion

#region Module D: Certificates (SCEP/PKCS/MDM) & Enterprise 802.1X Wi-Fi Diagnostics

function Get-StoreCertificatesAnalysis {
    param (
        [string]$StoreLocationName,
        [string]$StorePath
    )

    $certList = @()
    $now = Get-Date

    if (-not (Test-Path $StorePath)) {
        return $certList
    }

    $rawCerts = Get-ChildItem -Path $StorePath -ErrorAction SilentlyContinue
    foreach ($c in $rawCerts) {
        $daysRemaining = [math]::Round(($c.NotAfter - $now).TotalDays, 0)
        $isExpired = ($c.NotAfter -lt $now)
        $isNotYetValid = ($c.NotBefore -gt $now)

        $ekuOids = @()
        $ekuNames = @()
        $ekuList = Get-SafePropertyValue -InputObject $c -PropertyName "EnhancedKeyUsageList"
        if ($ekuList) {
            foreach ($eku in $ekuList) {
                $oidVal = Get-SafePropertyValue -InputObject $eku -PropertyName "ObjectId"
                $friendlyVal = Get-SafePropertyValue -InputObject $eku -PropertyName "FriendlyName"
                if ($oidVal) { $ekuOids += $oidVal }
                if ($friendlyVal) { $ekuNames += $friendlyVal }
            }
        }

        $isClientAuth = ($ekuOids -contains "1.3.6.1.5.5.7.3.2")
        $isIntuneMdmCert = ($c.Issuer -match 'Microsoft Intune MDM Device CA|MS-Organization-Access|MS-Organization-P2P-Access')

        $certCategory = "General"
        if ($isIntuneMdmCert) {
            $certCategory = "Intune MDM Device Cert"
        } elseif ($isClientAuth) {
            $certCategory = "802.1X / VPN Client Auth"
        }

        $thumbprintVal = Get-SafePropertyValue -InputObject $c -PropertyName "Thumbprint" -DefaultValue ""
        $shortThumb = if ($thumbprintVal.Length -ge 8) { $thumbprintVal.Substring(0, 8) + "..." } else { $thumbprintVal }

        $certList += [PSCustomObject]@{
            store         = $StoreLocationName
            category      = $certCategory
            subject       = Protect-SensitiveString -Value $c.Subject -Prefix "SUBJ"
            issuer        = if ($isIntuneMdmCert) { $c.Issuer } else { Protect-SensitiveString -Value $c.Issuer -Prefix "CA" }
            thumbprint    = Protect-SensitiveString -Value $shortThumb -Prefix "THUMB"
            notBeforeUtc  = $c.NotBefore.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            notAfterUtc   = $c.NotAfter.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            daysRemaining = $daysRemaining
            isExpired     = $isExpired
            isNotYetValid = $isNotYetValid
            hasPrivateKey = [bool]$c.HasPrivateKey
            isClientAuth  = $isClientAuth
            isIntuneMdm   = $isIntuneMdmCert
            ekuList       = ($ekuNames -join ", ")
        }
    }

    return $certList
}

function Get-ModuleDCertAndWifiData {
    param (
        [System.Collections.Generic.List[object]]$Findings
    )

    $machineCerts = @(Get-StoreCertificatesAnalysis -StoreLocationName "LocalMachine" -StorePath "Cert:\LocalMachine\My")
    $userCerts    = @(Get-StoreCertificatesAnalysis -StoreLocationName "CurrentUser" -StorePath "Cert:\CurrentUser\My")
    $allCerts     = @($machineCerts + $userCerts)

    $mdmCerts = @($machineCerts | Where-Object { $_.isIntuneMdm })
    if ($mdmCerts.Count -gt 0) {
        $expiredMdm = @($mdmCerts | Where-Object { $_.isExpired })
        if ($expiredMdm.Count -gt 0) {
            Add-Finding -FindingsList $Findings -Module "ModuleD" -CheckId "CERT-MDM-01" `
                -Title "Intune MDM Device Certificate" -Severity "Critical" `
                -ObservedValue "Expired ($($expiredMdm[0].notAfterUtc))" `
                -Summary "The Microsoft Intune MDM device certificate in LocalMachine\My has expired. Intune sync and check-ins will fail with HTTP 400/401." `
                -RemediationHint "Re-enroll device into Intune or check scheduled task 'Schedule #3 created by enrollment client' for cert renewal."
        } else {
            $minDays = ($mdmCerts | Measure-Object -Property daysRemaining -Minimum).Minimum
            Add-Finding -FindingsList $Findings -Module "ModuleD" -CheckId "CERT-MDM-01" `
                -Title "Intune MDM Device Certificate" -Severity "Pass" `
                -ObservedValue "Valid ($minDays days left)" `
                -Summary "Active Intune MDM device certificate verified in LocalMachine\My." -RemediationHint "None"
        }
    }

    $clientAuthCerts = @($allCerts | Where-Object { $_.isClientAuth })
    $brokenKeyCerts  = @($clientAuthCerts | Where-Object { -not $_.hasPrivateKey -and -not $_.isExpired })
    $expiringSoon    = @($clientAuthCerts | Where-Object { -not $_.isExpired -and $_.daysRemaining -le 30 })
    $expiredClient   = @($clientAuthCerts | Where-Object { $_.isExpired })

    if ($brokenKeyCerts.Count -gt 0) {
        Add-Finding -FindingsList $Findings -Module "ModuleD" -CheckId "CERT-KEY-02" `
            -Title "Client Authentication Certificate Private Keys" -Severity "Critical" `
            -ObservedValue "$($brokenKeyCerts.Count) Cert(s) Missing Private Key" `
            -Summary "A Client Authentication (802.1X/VPN) certificate exists without a bound private key. EAP-TLS authentication will fail." `
            -RemediationHint "Delete the orphaned certificate and trigger a new SCEP/PKCS profile sync from Intune."
    } elseif ($expiringSoon.Count -gt 0) {
        $soonest = ($expiringSoon | Measure-Object -Property daysRemaining -Minimum).Minimum
        Add-Finding -FindingsList $Findings -Module "ModuleD" -CheckId "CERT-EXP-03" `
            -Title "Client Authentication Certificate Expiration" -Severity "Warning" `
            -ObservedValue "Expiring in $soonest days" `
            -Summary "$($expiringSoon.Count) Client Authentication certificate(s) will expire within 30 days." `
            -RemediationHint "Verify SCEP/PKCS auto-renewal threshold in Intune certificate profile."
    } elseif ($clientAuthCerts.Count -gt 0 -and $expiredClient.Count -eq $clientAuthCerts.Count) {
        Add-Finding -FindingsList $Findings -Module "ModuleD" -CheckId "CERT-EXP-03" `
            -Title "Client Authentication Certificate Expiration" -Severity "Critical" `
            -ObservedValue "All Expired ($($expiredClient.Count))" `
            -Summary "All Client Authentication certificates on this device have expired. Corporate 802.1X Wi-Fi/VPN access will be rejected." `
            -RemediationHint "Renew SCEP/PKCS certificates via Intune sync or on-premises CA auto-enrollment."
    } elseif ($clientAuthCerts.Count -gt 0) {
        Add-Finding -FindingsList $Findings -Module "ModuleD" -CheckId "CERT-AUTH-04" `
            -Title "802.1X / VPN Client Certificates" -Severity "Pass" `
            -ObservedValue "$($clientAuthCerts.Count) Valid Cert(s)" `
            -Summary "Valid Client Authentication certificates with intact private keys found." -RemediationHint "None"
    } else {
        Add-Finding -FindingsList $Findings -Module "ModuleD" -CheckId "CERT-AUTH-04" `
            -Title "802.1X / VPN Client Certificates" -Severity "Info" `
            -ObservedValue "0 Client Auth Certs" `
            -Summary "No Client Authentication (EAP-TLS) certificates deployed in My stores." -RemediationHint "None"
    }

    $wlanService = Get-Service -Name "WlanSvc" -ErrorAction SilentlyContinue
    $wlanServiceStatus = if ($wlanService) { $wlanService.Status.ToString() } else { "NotInstalled" }

    $null = & netsh.exe wlan show profiles 2>&1
    $hasWirelessHardware = ($LASTEXITCODE -eq 0)

    $wifiProfiles = @()
    $enterpriseWifiProfiles = @()
    $wlanErrors72h = @()

    if (-not $hasWirelessHardware) {
        Add-Finding -FindingsList $Findings -Module "ModuleD" -CheckId "WIFI-HW-01" `
            -Title "Wireless / 802.1X Subsystem" -Severity "Info" `
            -ObservedValue "No Wireless Adapter Active" `
            -Summary "No active Wi-Fi interface detected on this system (Ethernet-only or wireless adapter disabled)." `
            -RemediationHint "None"
    } else {
        if ($wlanServiceStatus -ne "Running") {
            Add-Finding -FindingsList $Findings -Module "ModuleD" -CheckId "WIFI-SVC-01" `
                -Title "WLAN AutoConfig Service (WlanSvc)" -Severity "Critical" `
                -ObservedValue $wlanServiceStatus `
                -Summary "WLAN AutoConfig service is not running. Wi-Fi and 802.1X supplicant cannot operate." `
                -RemediationHint "Start and set 'WlanSvc' service to Automatic startup."
        }

        $profilesRaw = & netsh.exe wlan show profiles 2>&1
        $profileNames = @()
        foreach ($line in $profilesRaw) {
            if ($line -match '^\s*[^:]+:\s*(.+?)\s*$') {
                $candidate = $matches[1].Trim()
                if (-not [string]::IsNullOrWhiteSpace($candidate) -and $candidate -ne '<None>') {
                    $profileNames += $candidate
                }
            }
        }

        foreach ($pName in ($profileNames | Select-Object -Unique)) {
            $detailRaw = (& netsh.exe wlan show profile name="$pName" 2>&1) | Out-String
            $isEnterprise8021x = ($detailRaw -match '802\.1X|WPA2-Enterprise|WPA3-Enterprise|EAP')
            $authType = "Personal / Open"
            if ($detailRaw -match 'WPA3-Enterprise') { $authType = "WPA3-Enterprise (802.1X)" }
            elseif ($detailRaw -match 'WPA2-Enterprise') { $authType = "WPA2-Enterprise (802.1X)" }
            elseif ($detailRaw -match '802\.1X') { $authType = "802.1X Enterprise" }
            elseif ($detailRaw -match 'WPA2-Personal') { $authType = "WPA2-Personal" }
            elseif ($detailRaw -match 'WPA3-Personal') { $authType = "WPA3-Personal" }

            $profileObj = [PSCustomObject]@{
                ssidName       = Protect-SensitiveString -Value $pName -Prefix "SSID"
                authentication = $authType
                isEnterprise   = $isEnterprise8021x
            }
            $wifiProfiles += $profileObj
            if ($isEnterprise8021x) {
                $enterpriseWifiProfiles += $profileObj
            }
        }

        $wlanEventKB = @{
            8002  = "WLAN connection failed (check reason code: 802.1X auth failure, timeout, or invalid certificate)."
            11004 = "Wireless security (802.1X / EAP) authentication stopped before completion."
            11005 = "Wireless security (802.1X / EAP) authentication failed (RADIUS rejected credentials/certificate)."
            11006 = "Wireless 802.1X authentication restarted or timed out waiting for RADIUS/NPS server."
            12011 = "EAP authentication failed: Client or Server certificate validation error."
            12012 = "EAP authentication failed: Explicit failure received from RADIUS server."
            12013 = "EAP-TLS certificate error: Missing client certificate or untrusted Root CA."
        }

        $startTime = (Get-Date).AddHours(-72)
        try {
            $wlanEvents = Get-WinEvent -FilterHashtable @{
                LogName   = "Microsoft-Windows-WLAN-AutoConfig/Operational"
                Id        = @(8002, 11004, 11005, 11006, 12011, 12012, 12013)
                StartTime = $startTime
            } -MaxEvents 20 -ErrorAction Stop

            foreach ($wev in $wlanEvents) {
                $wMsg = $wev.Message
                $reasonCode = $null
                if ($wMsg -match '(0x[0-9a-fA-F]{6,8})') {
                    $reasonCode = $matches[1].ToLower()
                }

                $explanation = if ($wlanEventKB.ContainsKey([int]$wev.Id)) {
                    $wlanEventKB[[int]$wev.Id]
                } else {
                    "WLAN 802.1X authentication error."
                }

                $wlanErrors72h += [PSCustomObject]@{
                    timeUtc          = $wev.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                    eventId          = $wev.Id
                    reasonCode       = $reasonCode
                    humanExplanation = $explanation
                    rawMessage       = if ($wMsg.Length -gt 320) { $wMsg.Substring(0, 320) + "..." } else { $wMsg }
                }
            }
        } catch {
            # Operational log empty or disabled
        }

        if ($wlanErrors72h.Count -gt 0) {
            $eventIdsStr = ($wlanErrors72h | Select-Object -ExpandProperty eventId -Unique) -join ", "
            Add-Finding -FindingsList $Findings -Module "ModuleD" -CheckId "WIFI-8021X-02" `
                -Title "Enterprise Wi-Fi / 802.1X Authentication Failures (72h)" -Severity "Critical" `
                -ObservedValue "$($wlanErrors72h.Count) Failures (Event IDs: $eventIdsStr)" `
                -Summary "Recent 802.1X/EAP wireless authentication failures detected. Common causes: untrusted RADIUS Root CA, missing client cert, or NPS policy mismatch." `
                -RemediationHint "Verify Trusted Root CA profile is deployed via Intune and inspect Event ID 12011/12013 details below."
        } elseif ($enterpriseWifiProfiles.Count -gt 0) {
            Add-Finding -FindingsList $Findings -Module "ModuleD" -CheckId "WIFI-8021X-02" `
                -Title "Enterprise Wi-Fi / 802.1X Health" -Severity "Pass" `
                -ObservedValue "$($enterpriseWifiProfiles.Count) Enterprise Profile(s), 0 Errors" `
                -Summary "Corporate 802.1X Wi-Fi profile configured with no authentication failures in the past 72 hours." `
                -RemediationHint "None"
        } else {
            Add-Finding -FindingsList $Findings -Module "ModuleD" -CheckId "WIFI-8021X-02" `
                -Title "Enterprise Wi-Fi Profiles" -Severity "Info" `
                -ObservedValue "0 Enterprise Profiles" `
                -Summary "Wireless hardware is active, but no 802.1X Enterprise Wi-Fi profiles are configured." `
                -RemediationHint "None"
        }
    }

    return [PSCustomObject]@{
        certificates = [PSCustomObject]@{
            machineStoreCount = $machineCerts.Count
            userStoreCount    = $userCerts.Count
            clientAuthCount   = $clientAuthCerts.Count
            intuneMdmCerts    = $mdmCerts
            allCertificates   = $allCerts
        }
        wireless = [PSCustomObject]@{
            hasWirelessHardware    = $hasWirelessHardware
            wlanServiceStatus      = $wlanServiceStatus
            profiles               = $wifiProfiles
            enterpriseProfileCount = $enterpriseWifiProfiles.Count
            recent8021xErrors72h   = $wlanErrors72h
        }
    }
}

#endregion

#region Module E: Win32 Apps (IME Logs/Registry) & BitLocker/Storage Health

function Read-LogTailSafe {
    param (
        [string]$FilePath,
        [int]$MaxBytes = 1572864
    )

    if (-not (Test-Path $FilePath)) {
        return @()
    }

    $lines = [System.Collections.Generic.List[string]]::new()
    $fs = $null
    $sr = $null

    try {
        $fs = New-Object System.IO.FileStream($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        if ($fs.Length -gt $MaxBytes) {
            $fs.Seek(-$MaxBytes, [System.IO.SeekOrigin]::End) | Out-Null
        }
        $sr = New-Object System.IO.StreamReader($fs, [System.Text.Encoding]::UTF8)

        if ($fs.Position -gt 0) {
            $null = $sr.ReadLine()
        }

        while (-not $sr.EndOfStream) {
            $lines.Add($sr.ReadLine())
        }
    } catch {
        # Log file inaccessible
    } finally {
        if ($sr) { $sr.Dispose() }
        if ($fs) { $fs.Dispose() }
    }

    return $lines
}

function Get-ModuleEAppsAndStorageData {
    param (
        [System.Collections.Generic.List[object]]$Findings
    )

    $win32ErrorKB = @{
        "1603"       = "MSI Fatal Error during installation (1603). Check app-specific MSI log in C:\Windows\Temp or C:\ProgramData\Microsoft\IntuneManagementExtension\Logs."
        "1618"       = "Another installation is already in progress (1618). Windows Installer mutex was busy."
        "1619"       = "Installation package could not be opened (1619). Verify .intunewin source path or file integrity."
        "1605"       = "Uninstall failed because product is not currently installed (1605)."
        "3010"       = "Installation succeeded but a soft reboot is required (3010)."
        "0x87d1041c" = "Win32 App Detection Rule failed after installation completed (app installed, but Intune detection script/registry/file check returned false)."
        "0x87d30067" = "Content download or SHA256 hash verification failed (0x87d30067). Check proxy/firewall cache or CDN reachability."
        "0x80070002" = "System cannot find the file specified (0x80070002). Check install command line or setup executable name inside .intunewin."
        "0x80070005" = "Access Denied (0x80070005). App requires SYSTEM context or elevation permissions."
        "0x80070070" = "Insufficient disk space during Win32 app download or extraction (0x80070070)."
        "0x80070643" = "Fatal error during installation (0x80070643 / MSI 1603)."
    }

    $imeWin32RegBase = "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps"
    $trackedApps = @()
    $appNameLookup = @{}

    $imeLogPath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log"
    $imeLogExists = Test-Path $imeLogPath
    $recentImeErrors = @()

    if ($imeLogExists) {
        $tailLines = Read-LogTailSafe -FilePath $imeLogPath
        $cmTraceRegex = '^<!\[LOG\[(?<msg>.*?)\]LOG\]!><time="(?<time>[^"]+)"\s+date="(?<date>[^"]+)"\s+component="(?<comp>[^"]*)"\s+context="[^"]*"\s+type="(?<type>\d+)"'

        foreach ($line in $tailLines) {
            if ($line -match '"Id"\s*:\s*"([0-9a-fA-F-]{36})"\s*,\s*"Name"\s*:\s*"([^"]+)"') {
                $appGuidKey = $matches[1].ToLower()
                $rawAppName = $matches[2]
                if (-not $appNameLookup.ContainsKey($appGuidKey)) {
                    $appNameLookup[$appGuidKey] = $rawAppName
                }
            }

            if ($line -match $cmTraceRegex) {
                $logType = $matches['type']
                $msgBody = $matches['msg']
                if ($logType -eq '3' -or ($msgBody -match '\[Win32App\].*(failed|error|exit code|0x87d|1603|0x8007)')) {
                    $detectedCode = $null
                    if ($msgBody -match '(0x[0-9a-fA-F]{8})') {
                        $detectedCode = $matches[1].ToLower()
                    } elseif ($msgBody -match '(?:exit\s*code|lpExitCode)\s*[:=]\s*(-?\d+)') {
                        $detectedCode = $matches[1]
                    }

                    $hint = if ($detectedCode -and $win32ErrorKB.ContainsKey($detectedCode)) {
                        $win32ErrorKB[$detectedCode]
                    } else {
                        "Review Win32App command line, detection rule, and exit code behavior in Intune."
                    }

                    $cleanMsg = if ($msgBody.Length -gt 320) { $msgBody.Substring(0, 320) + "..." } else { $msgBody }
                    if ($Anonymize) {
                        $cleanMsg = $cleanMsg -replace '([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', '[MASKED-UPN]'
                    }

                    $recentImeErrors += [PSCustomObject]@{
                        timestamp        = "$($matches['date']) $($matches['time'])"
                        component        = $matches['comp']
                        detectedCode     = $detectedCode
                        humanExplanation = $hint
                        message          = $cleanMsg
                    }
                }
            }
        }
    }

    if ($recentImeErrors.Count -gt 15) {
        $recentImeErrors = @($recentImeErrors | Select-Object -Last 15)
    }

    if (Test-Path $imeWin32RegBase) {
        $contextKeys = Get-ChildItem -Path $imeWin32RegBase -ErrorAction SilentlyContinue
        foreach ($ctx in $contextKeys) {
            if ($ctx.PSChildName -eq 'Reporting') { continue }
            $installContext = if ($ctx.PSChildName -eq '00000000-0000-0000-0000-000000000000') { "System" } else { "User" }

            $appKeys = Get-ChildItem -Path $ctx.PSPath -ErrorAction SilentlyContinue
            foreach ($ak in $appKeys) {
                $rawKeyName = $ak.PSChildName
                $appGuid = ($rawKeyName -split '_')[0].ToLower()
                $appProps = Get-ItemProperty -Path $ak.PSPath -ErrorAction SilentlyContinue
                $stateJsonRaw = Get-SafePropertyValue -InputObject $appProps -PropertyName "EnforcementStateMessage"

                $enforcementState = $null
                $errorCodeHex = $null
                $statusLabel = "Unknown"

                if ($stateJsonRaw) {
                    try {
                        $stateObj = $stateJsonRaw | ConvertFrom-Json -ErrorAction Stop
                        $enforcementState = Get-SafePropertyValue -InputObject $stateObj -PropertyName "EnforcementState"
                        $errCodeNum = Get-SafePropertyValue -InputObject $stateObj -PropertyName "ErrorCode"
                        if ($null -ne $errCodeNum -and $errCodeNum -ne 0) {
                            $errorCodeHex = "0x" + ([Convert]::ToString([int64]$errCodeNum, 16)).ToLower().PadLeft(8, '0')
                            if ($errorCodeHex.Length -gt 10) {
                                $errorCodeHex = "0x" + $errorCodeHex.Substring($errorCodeHex.Length - 8)
                            }
                        }
                    } catch {
                        # Malformed JSON in registry
                    }
                }

                switch ($enforcementState) {
                    1000 { $statusLabel = "Installed" }
                    2000 { $statusLabel = "In Progress" }
                    2009 { $statusLabel = "Pending Reboot" }
                    4000 { $statusLabel = "Not Applicable" }
                    5000 { $statusLabel = "Failed" }
                    5001 { $statusLabel = "Failed (Dependency)" }
                    5003 { $statusLabel = "Failed (Download/Hash)" }
                    5005 { $statusLabel = "Failed (Detection Rule)" }
                    default { if ($null -ne $enforcementState) { $statusLabel = "State ($enforcementState)" } }
                }

                $resolvedName = if ($appNameLookup.ContainsKey($appGuid)) { $appNameLookup[$appGuid] } else { "Win32App-$($appGuid.Substring(0,8))" }
                $explanation = if ($errorCodeHex -and $win32ErrorKB.ContainsKey($errorCodeHex)) { $win32ErrorKB[$errorCodeHex] } else { $null }

                $trackedApps += [PSCustomObject]@{
                    appId            = Protect-SensitiveString -Value $appGuid -Prefix "APPID"
                    appName          = Protect-SensitiveString -Value $resolvedName -Prefix "APP"
                    context          = $installContext
                    enforcementState = $enforcementState
                    status           = $statusLabel
                    errorCode        = $errorCodeHex
                    remediationNote  = $explanation
                }
            }
        }
    }

    $failedWin32Apps = @($trackedApps | Where-Object { $_.status -like "Failed*" })
    if ($failedWin32Apps.Count -gt 0) {
        $failedSummaryList = ($failedWin32Apps | ForEach-Object { "$($_.appName) [$($_.status) $($_.errorCode)]" }) -join "; "
        Add-Finding -FindingsList $Findings -Module "ModuleE" -CheckId "APP-WIN32-01" `
            -Title "Intune Win32 Application Deployments" -Severity "Critical" `
            -ObservedValue "$($failedWin32Apps.Count)/$($trackedApps.Count) Failed" `
            -Summary "Detected failed Win32 app deployments: $failedSummaryList" `
            -RemediationHint "Check mapped error codes in the Win32 Apps & IME Logs section and verify detection rules."
    } elseif ($trackedApps.Count -gt 0) {
        Add-Finding -FindingsList $Findings -Module "ModuleE" -CheckId "APP-WIN32-01" `
            -Title "Intune Win32 Application Deployments" -Severity "Pass" `
            -ObservedValue "$($trackedApps.Count) App(s) Healthy" `
            -Summary "All tracked Intune Win32 applications are installed or compliant." -RemediationHint "None"
    } else {
        Add-Finding -FindingsList $Findings -Module "ModuleE" -CheckId "APP-WIN32-01" `
            -Title "Intune Win32 Application Deployments" -Severity "Info" `
            -ObservedValue "0 Win32 Apps Tracked" `
            -Summary "No Win32 applications recorded in IME registry on this device." -RemediationHint "None"
    }

    if ($recentImeErrors.Count -gt 0 -and $failedWin32Apps.Count -eq 0) {
        Add-Finding -FindingsList $Findings -Module "ModuleE" -CheckId "APP-IMELOG-02" `
            -Title "IME Log Error Entries" -Severity "Warning" `
            -ObservedValue "$($recentImeErrors.Count) Error Lines" `
            -Summary "IntuneManagementExtension.log contains recent error entries (e.g., PowerShell remediation/script or transient Win32 errors)." `
            -RemediationHint "Review parsed IME error messages below."
    }

    $sysDriveLetter = $env:SystemDrive
    $sysDisk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$sysDriveLetter'" -ErrorAction SilentlyContinue
    $freeSpaceGb = $null
    $totalSpaceGb = $null
    $freePercent = $null

    if ($sysDisk -and $sysDisk.Size -gt 0) {
        $freeSpaceGb  = [math]::Round($sysDisk.FreeSpace / 1GB, 1)
        $totalSpaceGb = [math]::Round($sysDisk.Size / 1GB, 1)
        $freePercent  = [math]::Round(($sysDisk.FreeSpace / $sysDisk.Size) * 100, 1)

        if ($freeSpaceGb -lt 5) {
            Add-Finding -FindingsList $Findings -Module "ModuleE" -CheckId "STOR-SPACE-01" `
                -Title "System Drive Free Space ($sysDriveLetter)" -Severity "Critical" `
                -ObservedValue "$freeSpaceGb GB Free ($freePercent%)" `
                -Summary "Critically low disk space on $sysDriveLetter. Windows Updates and Intune Win32 app caching (IMECache) will fail." `
                -RemediationHint "Free up at least 15 GB of space on $sysDriveLetter and clear C:\Windows\IMECache if stale."
        } elseif ($freeSpaceGb -lt 15) {
            Add-Finding -FindingsList $Findings -Module "ModuleE" -CheckId "STOR-SPACE-01" `
                -Title "System Drive Free Space ($sysDriveLetter)" -Severity "Warning" `
                -ObservedValue "$freeSpaceGb GB Free ($freePercent%)" `
                -Summary "Low disk space on $sysDriveLetter (<15 GB). Large Win32 apps or Feature Updates may fail." `
                -RemediationHint "Clean temporary files or run Storage Sense."
        } else {
            Add-Finding -FindingsList $Findings -Module "ModuleE" -CheckId "STOR-SPACE-01" `
                -Title "System Drive Free Space ($sysDriveLetter)" -Severity "Pass" `
                -ObservedValue "$freeSpaceGb GB / $totalSpaceGb GB Free ($freePercent%)" `
                -Summary "Sufficient free storage available for Intune app caching and OS operations." -RemediationHint "None"
        }
    }

    $physicalDisks = @()
    $unhealthyDisks = @()
    try {
        $pDisks = Get-PhysicalDisk -ErrorAction Stop
        foreach ($pd in $pDisks) {
            $dObj = [PSCustomObject]@{
                friendlyName      = $pd.FriendlyName
                mediaType         = [string]$pd.MediaType
                busType           = [string]$pd.BusType
                healthStatus      = [string]$pd.HealthStatus
                operationalStatus = [string]$pd.OperationalStatus
                sizeGb            = [math]::Round($pd.Size / 1GB, 1)
            }
            $physicalDisks += $dObj
            if ($pd.HealthStatus -ne 'Healthy') {
                $unhealthyDisks += $dObj
            }
        }
    } catch {
        $wmiDisks = Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction SilentlyContinue
        foreach ($wd in $wmiDisks) {
            $dObj = [PSCustomObject]@{
                friendlyName      = $wd.Model
                mediaType         = $wd.MediaType
                busType           = $wd.InterfaceType
                healthStatus      = if ($wd.Status -eq 'OK') { 'Healthy' } else { $wd.Status }
                operationalStatus = $wd.Status
                sizeGb            = [math]::Round($wd.Size / 1GB, 1)
            }
            $physicalDisks += $dObj
            if ($wd.Status -ne 'OK') {
                $unhealthyDisks += $dObj
            }
        }
    }

    if ($unhealthyDisks.Count -gt 0) {
        $badNames = ($unhealthyDisks | Select-Object -ExpandProperty friendlyName) -join ", "
        Add-Finding -FindingsList $Findings -Module "ModuleE" -CheckId "STOR-DISK-02" `
            -Title "Physical Disk Hardware Health (SMART)" -Severity "Critical" `
            -ObservedValue "Unhealthy ($badNames)" `
            -Summary "Physical storage hardware reported degraded or unhealthy SMART status. High risk of OS corruption or boot failure." `
            -RemediationHint "Back up user data immediately and schedule SSD/NVMe hardware replacement."
    } elseif ($physicalDisks.Count -gt 0) {
        Add-Finding -FindingsList $Findings -Module "ModuleE" -CheckId "STOR-DISK-02" `
            -Title "Physical Disk Hardware Health (SMART)" -Severity "Pass" `
            -ObservedValue "$($physicalDisks.Count) Disk(s) Healthy" `
            -Summary "All physical storage drives report Healthy status." -RemediationHint "None"
    }

    $bitlockerInfo = $null
    try {
        $blVol = Get-CimInstance -Namespace "root\cimv2\security\microsoftvolumeencryption" `
            -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$sysDriveLetter'" -ErrorAction Stop

        if ($blVol) {
            $protStatus = [int]$blVol.ProtectionStatus
            $convStatus = [int]$blVol.ConversionStatus

            $protLabel = switch ($protStatus) {
                0 { "Off / Suspended" }
                1 { "On (Protected)" }
                default { "Unknown ($protStatus)" }
            }

            $convLabel = switch ($convStatus) {
                0 { "Fully Decrypted" }
                1 { "Fully Encrypted" }
                2 { "Encryption In Progress" }
                3 { "Decryption In Progress" }
                4 { "Encryption Paused" }
                5 { "Decryption Paused" }
                default { "Unknown ($convStatus)" }
            }

            $kpResult = Invoke-CimMethod -InputObject $blVol -MethodName "GetKeyProtectors" -Arguments @{ KeyProtectorType = 0 } -ErrorAction SilentlyContinue
            $rawKpIds = Get-SafePropertyValue -InputObject $kpResult -PropertyName "VolumeKeyProtectorID"
            $kpIds = if ($rawKpIds) { @($rawKpIds) } else { @() }

            $protectorTypes = @()
            foreach ($kpId in $kpIds) {
                $typeRes = Invoke-CimMethod -InputObject $blVol -MethodName "GetKeyProtectorType" -Arguments @{ VolumeKeyProtectorID = $kpId } -ErrorAction SilentlyContinue
                $kpTypeNum = Get-SafePropertyValue -InputObject $typeRes -PropertyName "KeyProtectorType"
                if ($null -ne $kpTypeNum) {
                    $tName = switch ([int]$kpTypeNum) {
                        1 { "TPM" }
                        2 { "ExternalKey" }
                        3 { "RecoveryPassword" }
                        4 { "TPM+PIN" }
                        5 { "TPM+StartupKey" }
                        6 { "TPM+PIN+StartupKey" }
                        7 { "PublicKey" }
                        8 { "Passphrase" }
                        9 { "TpmCertificate" }
                        10 { "CryptoApiNextGen" }
                        default { "Type-$kpTypeNum" }
                    }
                    $protectorTypes += $tName
                }
            }

            $hasRecoveryPassword = ($protectorTypes -contains "RecoveryPassword")

            $bitlockerInfo = [PSCustomObject]@{
                driveLetter         = $sysDriveLetter
                protectionStatus    = $protLabel
                conversionStatus    = $convLabel
                keyProtectors       = $protectorTypes
                hasRecoveryPassword = $hasRecoveryPassword
            }

            if ($protStatus -eq 1 -and $hasRecoveryPassword) {
                Add-Finding -FindingsList $Findings -Module "ModuleE" -CheckId "SEC-BITL-01" `
                    -Title "BitLocker Drive Encryption ($sysDriveLetter)" -Severity "Pass" `
                    -ObservedValue "$convLabel ($($protectorTypes -join ' + '))" `
                    -Summary "BitLocker protection is active with TPM and Recovery Password key protectors configured." -RemediationHint "None"
            } elseif ($protStatus -eq 1 -and -not $hasRecoveryPassword) {
                Add-Finding -FindingsList $Findings -Module "ModuleE" -CheckId "SEC-BITL-01" `
                    -Title "BitLocker Recovery Key Protector" -Severity "Warning" `
                    -ObservedValue "Encrypted Without Recovery Password" `
                    -Summary "BitLocker is active, but no 48-digit RecoveryPassword protector was found. Entra ID recovery key backup may fail." `
                    -RemediationHint "Run 'manage-bde -protectors -add $sysDriveLetter -RecoveryPassword' and escrow to Entra ID."
            } elseif ($convStatus -eq 1 -and $protStatus -eq 0) {
                Add-Finding -FindingsList $Findings -Module "ModuleE" -CheckId "SEC-BITL-01" `
                    -Title "BitLocker Protection Suspended" -Severity "Warning" `
                    -ObservedValue "Encrypted (Protection Off)" `
                    -Summary "Volume is encrypted, but BitLocker protection is currently suspended. Intune compliance policies will mark device non-compliant." `
                    -RemediationHint "Resume BitLocker protection via 'Resume-BitLocker -MountPoint $sysDriveLetter'."
            } else {
                Add-Finding -FindingsList $Findings -Module "ModuleE" -CheckId "SEC-BITL-01" `
                    -Title "BitLocker Drive Encryption ($sysDriveLetter)" -Severity "Warning" `
                    -ObservedValue "$convLabel (Protection: $protLabel)" `
                    -Summary "OS drive is not protected by BitLocker encryption." `
                    -RemediationHint "Verify Intune Endpoint Security Disk Encryption policy or TPM 2.0 readiness."
            }
        }
    } catch {
        $bitlockerInfo = [PSCustomObject]@{
            driveLetter = $sysDriveLetter
            error       = "Access Denied (Requires Administrator privileges to query BitLocker WMI)"
        }
        Add-Finding -FindingsList $Findings -Module "ModuleE" -CheckId "SEC-BITL-01" `
            -Title "BitLocker Drive Encryption ($sysDriveLetter)" -Severity "Warning" `
            -ObservedValue "Access Denied" `
            -Summary "Could not read BitLocker status. Tool requires Administrator privileges for volume encryption WMI." `
            -RemediationHint "Re-run AutopilotDoctor as Administrator."
    }

    return [PSCustomObject]@{
        win32Apps = [PSCustomObject]@{
            imeLogPresent     = $imeLogExists
            trackedAppCount   = $trackedApps.Count
            failedAppCount    = $failedWin32Apps.Count
            applications      = $trackedApps
            recentImeErrors   = $recentImeErrors
        }
        storage = [PSCustomObject]@{
            systemDrive      = $sysDriveLetter
            freeSpaceGb      = $freeSpaceGb
            totalSpaceGb     = $totalSpaceGb
            freeSpacePercent = $freePercent
            physicalDisks    = $physicalDisks
            bitlocker        = $bitlockerInfo
        }
    }
}

#endregion

#region Main Execution & Payload Assembly

$findings = [System.Collections.Generic.List[object]]::new()
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
$csInfo = Get-CimInstance -ClassName Win32_ComputerSystem

$moduleAData = Get-ModuleAIdentityData -Findings $findings
$moduleBData = Get-ModuleBIntuneMdmData -Findings $findings
$moduleCData = Get-ModuleCNetworkData -Findings $findings
$moduleDData = Get-ModuleDCertAndWifiData -Findings $findings
$moduleEData = Get-ModuleEAppsAndStorageData -Findings $findings

$criticalCount = @($findings | Where-Object { $_.severity -eq 'Critical' }).Count
$warningCount  = @($findings | Where-Object { $_.severity -eq 'Warning' }).Count
$passCount     = @($findings | Where-Object { $_.severity -eq 'Pass' }).Count
$infoCount     = @($findings | Where-Object { $_.severity -eq 'Info' }).Count

$overallHealth = if ($criticalCount -gt 0) { "Critical" } elseif ($warningCount -gt 0) { "Warning" } else { "Healthy" }

$diagnosticPayload = [PSCustomObject]@{
    meta = [PSCustomObject]@{
        toolName       = "AutopilotDoctor"
        schemaVersion  = "1.3.0"
        generatedAtUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        anonymized     = [bool]$Anonymize
        isAdmin        = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    system = [PSCustomObject]@{
        hostname     = Protect-SensitiveString -Value $env:COMPUTERNAME -Prefix "HOST"
        manufacturer = $csInfo.Manufacturer
        model        = $csInfo.Model
        osCaption    = $osInfo.Caption
        osBuild      = "$($osInfo.Version) (Build $($osInfo.BuildNumber))"
        uptimeHours  = [math]::Round(((Get-Date) - $osInfo.LastBootUpTime).TotalHours, 1)
    }
    summary = [PSCustomObject]@{
        overallHealth = $overallHealth
        criticalCount = $criticalCount
        warningCount  = $warningCount
        passCount     = $passCount
        infoCount     = $infoCount
    }
    findings = $findings
    modules  = [PSCustomObject]@{
        moduleA_Identity       = $moduleAData
        moduleB_IntuneMdm      = $moduleBData
        moduleC_Network        = $moduleCData
        moduleD_CertsAndWifi   = $moduleDData
        moduleE_AppsAndStorage = $moduleEData
    }
}

$jsonOutput = ($diagnosticPayload | ConvertTo-Json -Depth 6) -replace '\\u0027', "'"

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $jsonOutput | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
}

return $jsonOutput

#endregion