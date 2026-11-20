# AutopilotDoctor

**Portable, zero-telemetry Windows diagnostic engine for Windows Autopilot, Entra ID, Intune MDM, SSL/TLS inspection, SCEP/PKCS certificates, and 802.1X Wi-Fi.**

AutopilotDoctor inspects critical endpoint states in ~15 seconds and outputs a standalone, offline-ready HTML dashboard report—eliminating the need to manually dig through `dsregcmd`, Event Viewer logs, registry hives, and Intune Management Extension (IME) logs.

---

## Key Diagnostic Modules

- **Module A — Identity & Hardware Attestation:** Parses `dsregcmd /status`, Primary Refresh Token (PRT) health, `KeySignTest`, recovery state, and TPM 2.0 readiness.
- **Module B — Intune MDM & Sync Health:** Audits `MS DM Server` enrollment keys, `EnterpriseMgmt` scheduled tasks, last check-in delta, IME service status, and translates 72-hour Event Viewer hex error codes.
- **Module C — Network & SSL/TLS Inspection:** Tests TCP 443 reachability and latency across 12 required Microsoft endpoints, flags User vs. SYSTEM WinHTTP proxy mismatches, and detects SSL/TLS MITM proxy interception (Zscaler, Fortinet, Palo Alto, Netskope).
- **Module D — Certificates & 802.1X Wireless:** Verifies `LocalMachine\My` and `CurrentUser\My` certificates for private key presence and expiration, and diagnoses WLAN AutoConfig 802.1X/EAP RADIUS failures.
- **Module E — Win32 Apps & BitLocker:** Maps Win32 app installation states and exit codes (`1603`, `0x87d1041c`, etc.), checks system drive capacity, NVMe/SSD SMART health, and BitLocker key protectors.

---

## Privacy & Security Architecture

- **100% Local Execution:** No diagnostic data, tenant IDs, or logs are ever transmitted to external servers.
- **Built-in PII Anonymizer:** One-click SHA-256 masking for Hostname, Tenant ID, UPN, Wi-Fi SSID, and application names so reports can be safely attached to vendor support tickets.
- **Read-Only Engine:** Strictly non-destructive; never modifies registry values, certificates, or MDM configurations.

---

## Editions

| Feature | Free Community Edition | Pro SysAdmin ($39) | MSP & Team Pack ($149) |
| :--- | :---: | :---: | :---: |
| Full 5-Module Diagnostic Scan | Yes | Yes | Yes |
| Interactive Dark/Light HTML Report | Yes | Yes | Yes |
| SSL/TLS MITM & Proxy Mismatch Detection | Yes | Yes | Yes |
| One-Click PII Anonymizer | Yes | Yes | Yes |
| Copy-Paste Remediation Commands & CLI Fixes | Locked | **Unlocked** | **Unlocked** |
| Hex Error Code Root-Cause Explanations | Locked | **Unlocked** | **Unlocked** |
| Raw JSON Export for Automation | Locked | **Unlocked** | **Unlocked** |
| 30-Day Offline License Cache (OOBE Ready) | — | **Yes (3 Seats)** | **Yes (15 Seats)** |

- **Download Free Edition:** [GitHub Releases](../../releases/latest)
- **Get Pro / MSP License:** [Official Storefront](https://autopilotdoctor.lemonsqueezy.com)