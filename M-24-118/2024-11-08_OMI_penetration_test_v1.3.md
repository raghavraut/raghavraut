COPPERLINE SECURITY - trading name of D. Whitfield, independent consultant
CONFIDENTIAL - TLP:AMBER
PREPARED SOLELY FOR: the Principal (identity withheld; engagement pseudonym
OSTRANDER METALWORKS, INC. / "OMI" used throughout per CLS document policy DP-4)
DISTRIBUTION: T. SOKOL (CIO), R. EMMONS (DIR. IT), EXTERNAL AUDIT PARTNER (SUMMARY ONLY)
ENGAGEMENT: M-24-118
DOCUMENT: INTERNAL NETWORK & EXTERNAL PERIMETER PENETRATION TEST, v1.3
DATE: 2024-11-08
AUTHORS: D. WHITFIELD, A. OSEI (subcontract)
IDENTIFIERS: client legal name, addresses, personnel names and domains are DP-4
pseudonyms. the pseudonym-to-principal mapping exists only in the signed
authorization letter, which is not appended to any deliverable.

NOTE: v1.3 corrects the CVSS vector on F-04 and removes two informational items at the Client's request. v1.2 withdrawn. Do not distribute prior versions.

----------------------------------------------------------------
1. EXECUTIVE SUMMARY
----------------------------------------------------------------

Copperline Security ("CLS") performed a combined external and internal penetration test of OMI environments between 2024-10-14 and 2024-10-25, under the authorization letter signed 2024-09-30 (see M-24-118_scope_and_roe.md).

Overall posture: REQUIRES SIGNIFICANT IMPROVEMENT.

Within eleven (11) business days, two consultants achieved domain administrator privileges on the corporate Active Directory domain and accessed the ERP database server. No exploitation of the plant-floor (OT) network was attempted; one exposure was identified by observation only (F-05) and is reported for awareness.

Finding distribution: 2 Critical / 2 High / 2 Medium / 1 Low.

Recurring themes:

1. Patch management. Internet-facing collaboration infrastructure retains known, publicly exploited remote code execution vulnerabilities from 2021 (F-01).
2. Credential hygiene. Reuse of local administrator passwords across the fleet, and plaintext credential storage on a broadly readable share, converted single host compromises into domain compromise (F-02, F-03).
3. Segmentation. Corporate, management, and plant networks share trust relationships that exceed operational need (F-05).

The Client's staff were professional and responsive throughout. This report should not be read as an indictment of individuals; the findings below are common to organizations of comparable size and are remediable in the ordinary course.

----------------------------------------------------------------
2. SCOPE & METHODOLOGY
----------------------------------------------------------------

In scope: one (1) public IPv4 block; OMI corporate VLANs 10.24.0.0/16 and 10.25.0.0/16; Active Directory forest omi.local; hosted email tenant (configuration review only).
All client-side identifiers in this document are DP-4 pseudonyms; internal ranges and hostnames as tested under pseudonym. Out of scope: plant-floor OT networks, hosted payroll provider, production ERP (destructive testing prohibited; read-only access authorized).

Methodology aligned to NIST SP 800-115 and the Penetration Testing Execution Standard (PTES). Web application testing, where applicable, followed OWASP WSTG 4.2. Social engineering phase 1 (simulated phishing) conducted under separate consent, 2024-10-21.

All testing accounts were created with the Client's knowledge and are listed in Appendix B. Evidence containing credentials has been redacted in this document; unredacted evidence was delivered once, encrypted, per ROE 6, and CLS retained no copy per ROE 7.

----------------------------------------------------------------
3. FINDINGS
----------------------------------------------------------------

F-01  CRITICAL  CVSS 9.8  AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
Internet-facing Exchange server unpatched against publicly exploited RCE.

The host identified as OMI-EXCH-01 (public address redacted) answers on 443/tcp and presents build 15.1.2242.4, vulnerable to CVE-2021-34473 / CVE-2021-34523 ("ProxyShell"-class chaining). Public exploit code has existed since 2021; mass scanning for these endpoints is continuous and should be assumed.

Evidence (redacted):
  $ nmap -sV -p 443 <redacted>
  443/tcp open  ssl/http  Microsoft Exchange httpd ...
  (build fingerprint via outlook discovery endpoint)

Impact: unauthenticated remote code execution with SYSTEM privileges on a domain-joined host holding cached credentials for service accounts.

Recommendation: apply current cumulative update; enforce validateOnly-free management endpoint restrictions; move management interfaces behind VPN. Priority: immediate.

F-02  CRITICAL  CVSS 9.1  AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
Anonymous SMB access to share containing plaintext service-account credentials.

\\OMI-FS-02\Public\IT\scripts was readable by the DOMAIN USERS group and, due to a inherited ACE misconfiguration, anonymously. It contained service-accounts.xlsx listing 23 credentials in plaintext, including the domain administrator break-glass account.

Evidence (redacted):
  smbclient -N //OMI-FS-02/Public
  smb: \IT\scripts\> dir
  ... service-accounts.xlsx   48 KB

Impact: full domain compromise from any position with network reachability, without exploiting any software flaw.

Recommendation: rotate every credential in the file (assume all compromised); remove anonymous access; audit share ACLs forest-wide; adopt a secrets manager. Priority: immediate.

F-03  HIGH  CVSS 8.1  AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H
Shared local administrator password; lateral movement via pass-the-hash.

LAPS is not deployed. The local administrator hash recovered from OMI-WS-114 (a kiosk workstation) authenticated to 41 of 47 tested servers, including OMI-ERP-01.

Evidence (redacted): hash reuse matrix available in unredacted appendix only.

Recommendation: deploy LAPS; enforce unique local admin secrets; restrict workstation-to-server SMB where not required. Priority: 30 days.

F-04  HIGH  CVSS 7.6  AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N  (v1.3 corrected)
Kerberoastable service accounts with RC4-HMAC; weak secrets.

Fourteen (14) SPNs requested RC4-HMAC. Three hashes cracked in six (6) hours on a single workstation GPU, including svc-sql-prod whose secret was a dictionary word plus a two-digit year.

Recommendation: enforce AES, rotate service account secrets to 25+ characters, gMSA where possible. Priority: 30 days.

F-05  MEDIUM  CVSS 6.5  AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
Plant-floor NAS reachable from corporate VLAN with factory-default credentials.

OMI-NAS-PLANT1 (holding CAM program archives) accepted admin/<default>. Not exploited beyond authentication proof; reported for awareness. NOTE PER CLIENT REQUEST 11/12: retained in internal version only; excluded from external summary.

Recommendation: OT/IT segmentation; disable default accounts; firmware plan for EOL device. Priority: 60 days.

F-06  MEDIUM  CVSS 5.3  (simulation; no CVSS vector applies - retained for tracking)
Simulated phishing: 34% click-through, 11% credential submission.

Highest submission rates in shipping/receiving and AP. Recommend targeted module for AP (invoice-theme lures) given F-02's exposure pattern.

F-07  LOW  informational
Verbose banners and DNS expose internal host naming convention (OMI-<role>-NN), aiding enumeration.

----------------------------------------------------------------
4. CONCLUSION
----------------------------------------------------------------

OMI's compromise path followed the industry-standard shape: one unpatched edge device plus one credential hygiene failure equals domain ownership. Neither leg is expensive to remediate. CLS recommends a retest of F-01 through F-04 in 90 days.

----------------------------------------------------------------
APPENDIX A - TOOLING (VERSIONS AS TESTED)
----------------------------------------------------------------
Nmap 7.94; Burp Suite Professional 2024.9; Metasploit Framework 6.4.32 (validation only); CrackMapExec 6.1.0; Hashcat 6.2.6; BloodHound 4.3.1.

APPENDIX B - TEST ACCOUNTS
----------------------------------------------------------------
pentest-ext-01 .. 02 (external)
pentest-int-01 .. 03 (domain user, created 2024-10-14, disabled 2024-10-25)
credentials: [REDACTED - delivered once per ROE 6]

-- END --
