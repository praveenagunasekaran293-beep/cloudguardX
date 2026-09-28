import { db } from "./db.js";

export interface ScenarioDefinition {
  id: string;
  name: string;
  category: string;
  description: string;
  incident: any;
  events: any[];
  indicators: any[];
  vulnerability?: any;
  actions: any[];
}

export const DEMO_SCENARIOS: ScenarioDefinition[] = [
  {
    id: "scen-phishing-compromise",
    name: "1. Phishing-led Account Compromise",
    category: "Credential Access & Execution",
    description: "Executive assistant targeted with fake payroll portal spearphishing email, leading to credential harvesting, impossible-travel login from Eastern Europe, and PowerShell execution on the local host.",
    incident: {
      incidentId: "INC-SCEN-101",
      title: "Targeted Spearphishing with Lateral Endpoint Execution",
      description: "Synthetic simulation of an advanced phishing campaign bypassing basic SPF filters, harvesting corporate SSO credentials, and deploying an in-memory PowerShell stager on WS-FIN-04.",
      severity: "Critical",
      riskScore: 94,
      status: "Investigating",
      affectedUser: "sarah.jenkins@enterprise-corp.internal",
      affectedAssets: ["WS-FIN-04.corp.local", "Okta SSO Tenant", "CORP-DC-01"],
      relatedEvents: ["EVT-SCEN-101-A", "EVT-SCEN-101-B", "EVT-SCEN-101-C", "EVT-SCEN-101-D"],
      indicators: ["payroll-update-secure.top", "198.51.100.44", "hr-notice@portal-verify.cc", "SHA256:e3b0c442..."],
      timeline: [
        { time: "10:01:14", event: "Inbound Phishing Email bypassed SPF (Neutral)", source: "MailGuard SEG", severity: "High" },
        { time: "10:05:22", event: "User accessed URL & submitted credentials", source: "Palo Alto FW", severity: "Medium" },
        { time: "10:08:45", event: "Impossible Travel MFA login (Bucharest, RO)", source: "Okta IAM", severity: "Critical" },
        { time: "10:12:03", event: "Base64 PowerShell process spawned via Word", source: "CrowdStrike EDR", severity: "Critical" },
        { time: "10:14:19", event: "SMB reconnaissance probes sent to Domain Controller", source: "Splunk SIEM", severity: "High" },
      ],
      mitreTechniques: [
        { id: "T1566.002", name: "Spearphishing Link", tactic: "Initial Access", status: "Confirmed" },
        { id: "T1078.004", name: "Valid Accounts: Cloud Accounts", tactic: "Defense Evasion", status: "Confirmed" },
        { id: "T1059.001", name: "PowerShell Interpreter", tactic: "Execution", status: "Confirmed" },
        { id: "T1055", name: "Process Injection", tactic: "Privilege Escalation", status: "Confirmed" },
      ],
      recommendations: [
        "Network-isolate workstation WS-FIN-04 via EDR agent.",
        "Revoke Okta authentication sessions and reset password.",
        "Block destination IP 198.51.100.44 and domain payroll-update-secure.top on border firewalls.",
      ],
      riskBreakdown: {
        factors: [
          { name: "Synthetic Threat Intel Match", points: 25, reason: "Phishing domain matches high-confidence known kit." },
          { name: "Impossible Travel Login", points: 30, reason: "Session initiated from Bucharest 10m after Chicago access." },
          { name: "PowerShell Process Injection", points: 24, reason: "Encoded command spawned by winword.exe." },
          { name: "Critical Asset Target", points: 15, reason: "Workstation resides in Finance subnet." },
        ],
        totalScore: 94,
        maxScore: 100,
        explanation: "Critical composite risk (94/100) reflecting confirmed initial compromise and ongoing discovery.",
      },
    },
    events: [
      {
        eventId: "EVT-SCEN-101-A",
        timestamp: new Date(Date.now() - 45 * 60000).toISOString(),
        source: "MailGuard SEG",
        sourceType: "Email Gateway",
        user: "sarah.jenkins@enterprise-corp.internal",
        ip: "198.51.100.44",
        hostname: "mx01.corp",
        eventType: "Inbound Spearphishing",
        description: "Subject: URGENT - Verify Direct Deposit for Q3 Payroll.",
        severity: "High",
        indicators: ["payroll-update-secure.top", "198.51.100.44"],
        metadata: { dkim: "none", sender: "hr-notice@portal-verify.cc" },
      },
      {
        eventId: "EVT-SCEN-101-B",
        timestamp: new Date(Date.now() - 38 * 60000).toISOString(),
        source: "Okta IAM",
        sourceType: "Identity Provider",
        user: "sarah.jenkins",
        ip: "198.51.100.44",
        hostname: "auth.corp.local",
        eventType: "Impossible Travel Anomaly",
        description: "Concurrent session 4,500 miles away within 10 minutes.",
        severity: "Critical",
        indicators: ["198.51.100.44"],
        metadata: { country: "Romania", city: "Bucharest" },
      },
      {
        eventId: "EVT-SCEN-101-C",
        timestamp: new Date(Date.now() - 25 * 60000).toISOString(),
        source: "CrowdStrike Falcon",
        sourceType: "Endpoint EDR",
        user: "sarah.jenkins",
        ip: "10.0.4.88",
        hostname: "WS-FIN-04.corp.local",
        eventType: "Encoded PowerShell Injected",
        description: "Process winword.exe created hidden powershell.exe with -EncodedCommand.",
        severity: "Critical",
        indicators: ["WS-FIN-04", "powershell.exe"],
        metadata: { parent: "winword.exe", integrity: "High" },
      },
      {
        eventId: "EVT-SCEN-101-D",
        timestamp: new Date(Date.now() - 15 * 60000).toISOString(),
        source: "Splunk SIEM",
        sourceType: "SIEM Correlation",
        user: "sarah.jenkins",
        ip: "10.0.4.88",
        hostname: "WS-FIN-04.corp.local",
        eventType: "Internal Reconnaissance",
        description: "Port scan sweep against 10.0.0.5:445 (CORP-DC-01).",
        severity: "High",
        indicators: ["10.0.4.88", "10.0.0.5"],
        metadata: { sweptPorts: [445, 139, 88] },
      },
    ],
    indicators: [
      {
        id: "TI-SCEN-101-1",
        indicator: "payroll-update-secure.top",
        type: "Domain",
        status: "Malicious (Synthetic)",
        confidence: 97,
        source: "CyberSentinel Phishing Intel",
        threatGroup: "Simulated Threat Actor Red",
        tags: ["phishing", "payroll-spoof"],
        notes: "Newly observed domain imitating corporate payroll portal.",
      },
      {
        id: "TI-SCEN-101-2",
        indicator: "198.51.100.44",
        type: "IP",
        status: "Malicious (Synthetic)",
        confidence: 93,
        source: "AlienVault OTX Synthetic",
        threatGroup: "Simulated Threat Actor Red",
        tags: ["c2-relay", "proxy"],
        notes: "Origin IP for malicious session hijacking.",
      },
    ],
    actions: [
      {
        id: "ACT-SCEN-101-1",
        title: "Isolate WS-FIN-04 Endpoint",
        actionType: "Network Quarantine",
        description: "Sever all TCP/UDP connections on WS-FIN-04 via EDR agent.",
        riskLevel: "High",
      },
      {
        id: "ACT-SCEN-101-2",
        title: "Terminate Active User Sessions for sarah.jenkins",
        actionType: "IAM Revocation",
        description: "Kill active tokens across Okta and Office 365.",
        riskLevel: "Medium",
      },
    ],
  },
  {
    id: "scen-suspicious-auth",
    name: "2. Suspicious Authentication Activity",
    category: "Identity & Access Management",
    description: "Brute force and password spraying attack targeting multiple cloud accounts followed by an anomalous administrative privilege escalation.",
    incident: {
      incidentId: "INC-SCEN-102",
      title: "Distributed Password Spraying & IAM Role Escalation",
      description: "External attacker rotated across 40+ residential proxy IPs attempting standard enterprise passwords against Active Directory and AWS IAM accounts, achieving successful login on svc-devops.",
      severity: "High",
      riskScore: 82,
      status: "Investigating",
      affectedUser: "svc-devops@corp.internal",
      affectedAssets: ["Azure AD / Entra ID", "AWS IAM Master"],
      relatedEvents: ["EVT-SCEN-102-A", "EVT-SCEN-102-B", "EVT-SCEN-102-C"],
      indicators: ["192.0.2.145", "192.0.2.189", "svc-devops"],
      timeline: [
        { time: "08:15:00", event: "Password Spraying detected across 50 user accounts", source: "Azure Identity Protection", severity: "High" },
        { time: "08:21:10", event: "Successful login on service account svc-devops", source: "Okta IAM", severity: "Critical" },
        { time: "08:24:45", event: "Administrator role attached to svc-devops", source: "AWS IAM Audit", severity: "Critical" },
      ],
      mitreTechniques: [
        { id: "T1110.003", name: "Password Spraying", tactic: "Credential Access", status: "Confirmed" },
        { id: "T1078.002", name: "Domain Accounts", tactic: "Initial Access", status: "Confirmed" },
        { id: "T1098", name: "Account Manipulation", tactic: "Persistence", status: "Confirmed" },
      ],
      recommendations: [
        "Lock account svc-devops and invalidate all AWS STS session tokens.",
        "Revert attached AdministratorAccess IAM policy.",
        "Add IP range 192.0.2.0/24 to identity risk blocking list.",
      ],
      riskBreakdown: {
        factors: [
          { name: "Password Spray Volume", points: 28, reason: "1,200 failed attempts across 50 users." },
          { name: "High-Privilege Account Compromise", points: 32, reason: "Target account has deployment access." },
          { name: "Role Escalation Event", points: 22, reason: "Attached FullAdmin policy to service role." },
        ],
        totalScore: 82,
        maxScore: 100,
        explanation: "Risk 82/100 due to unauthorized privilege elevation on critical infrastructure account.",
      },
    },
    events: [
      {
        eventId: "EVT-SCEN-102-A",
        timestamp: new Date(Date.now() - 50 * 60000).toISOString(),
        source: "Azure Identity Protection",
        sourceType: "Cloud IAM",
        user: "Multiple (50 accounts)",
        ip: "192.0.2.145",
        hostname: "login.microsoftonline.com",
        eventType: "Password Spray Detection",
        description: "1,200 failed login attempts with single password attempts per user across distributed IPs.",
        severity: "High",
        indicators: ["192.0.2.145"],
        metadata: { usersTargeted: 50, failureCode: "AADSTS50126" },
      },
      {
        eventId: "EVT-SCEN-102-B",
        timestamp: new Date(Date.now() - 40 * 60000).toISOString(),
        source: "Okta IAM",
        sourceType: "Identity Provider",
        user: "svc-devops@corp.internal",
        ip: "192.0.2.189",
        hostname: "auth.corp.local",
        eventType: "Successful Brute-Forced Authentication",
        description: "Service account authenticated after 18 failed attempts from non-corporate ASN.",
        severity: "Critical",
        indicators: ["192.0.2.189", "svc-devops"],
        metadata: { authMethod: "PasswordOnly" },
      },
      {
        eventId: "EVT-SCEN-102-C",
        timestamp: new Date(Date.now() - 32 * 60000).toISOString(),
        source: "AWS CloudTrail",
        sourceType: "Cloud Audit",
        user: "svc-devops",
        ip: "192.0.2.189",
        hostname: "aws-iam-console",
        eventType: "AttachUserPolicy (AdministratorAccess)",
        description: "Service account granted itself AdministratorAccess policy arn.",
        severity: "Critical",
        indicators: ["arn:aws:iam::aws:policy/AdministratorAccess"],
        metadata: { targetUser: "svc-devops" },
      },
    ],
    indicators: [
      {
        id: "TI-SCEN-102-1",
        indicator: "192.0.2.145",
        type: "IP",
        status: "Malicious (Synthetic)",
        confidence: 89,
        source: "Synthetic Brute Force Tracker",
        threatGroup: "Spraying Cluster B",
        tags: ["password-spray", "proxy-pool"],
        notes: "Synthetic IP from distributed password spraying botnet.",
      },
    ],
    actions: [
      {
        id: "ACT-SCEN-102-1",
        title: "Disable svc-devops Account",
        actionType: "Identity Quarantine",
        description: "Disable user in Okta and Entra ID and terminate all active sessions.",
        riskLevel: "High",
      },
      {
        id: "ACT-SCEN-102-2",
        title: "Detach AdministratorAccess IAM Policy",
        actionType: "Cloud IAM Remediation",
        description: "Remove elevated policy attachment from compromised role.",
        riskLevel: "Medium",
      },
    ],
  },
  {
    id: "scen-suspicious-network",
    name: "3. Suspicious Network Activity",
    category: "Network Defense & C2",
    description: "Anomalous high-frequency DNS tunneling and outbound encrypted beaconing detected from a database server toward an unknown external node.",
    incident: {
      incidentId: "INC-SCEN-103",
      title: "DNS Tunneling Exfiltration & Outbound C2 Beaconing",
      description: "Database host DB-PROD-SQL-01 generated 14,000 sub-queries to *.sync-telemetry-cache.info with encoded TXT payloads matching DNS exfiltration profiles.",
      severity: "Critical",
      riskScore: 89,
      status: "Investigating",
      affectedUser: "sqladmin",
      affectedAssets: ["DB-PROD-SQL-01", "VLAN-DATABASE-ISOLATED"],
      relatedEvents: ["EVT-SCEN-103-A", "EVT-SCEN-103-B"],
      indicators: ["sync-telemetry-cache.info", "203.0.113.200"],
      timeline: [
        { time: "02:14:00", event: "Spike in anomalous high-entropy DNS queries", source: "Infoblox DNS FW", severity: "High" },
        { time: "02:22:15", event: "DNS Tunneling detection signature triggered", source: "Suricata NIDS", severity: "Critical" },
        { time: "02:28:40", event: "Outbound TLS connection to dynamic IP", source: "Palo Alto FW", severity: "High" },
      ],
      mitreTechniques: [
        { id: "T1071.004", name: "DNS Application Layer Protocol", tactic: "Command and Control", status: "Confirmed" },
        { id: "T1048.003", name: "Exfiltration Over Alternative Protocol (DNS)", tactic: "Exfiltration", status: "Confirmed" },
      ],
      recommendations: [
        "Sinkhole domain sync-telemetry-cache.info on internal recursive resolvers.",
        "Block outbound port 53 directly to the internet; force all queries through enterprise DNS proxy.",
        "Perform packet capture analysis on DB-PROD-SQL-01 network interface.",
      ],
      riskBreakdown: {
        factors: [
          { name: "Anomalous DNS Entropy Score", points: 30, reason: "Encoded Base32 subdomains indicate data tunneling." },
          { name: "Production Database Target", points: 35, reason: "Host stores PII and credit transactions." },
          { name: "Outbound C2 Flow Match", points: 24, reason: "Jittered TLS handshake to sinkholed foreign IP." },
        ],
        totalScore: 89,
        maxScore: 100,
        explanation: "Risk 89/100: Confirmed data exfiltration via DNS from production tier.",
      },
    },
    events: [
      {
        eventId: "EVT-SCEN-103-A",
        timestamp: new Date(Date.now() - 35 * 60000).toISOString(),
        source: "Infoblox DNS FW",
        sourceType: "DNS Security",
        user: "system",
        ip: "10.0.10.22",
        hostname: "DB-PROD-SQL-01",
        eventType: "DNS Tunneling Signature Alert",
        description: "14,500 TXT/NULL queries to subdomains of sync-telemetry-cache.info with average query length of 118 bytes.",
        severity: "Critical",
        indicators: ["sync-telemetry-cache.info"],
        metadata: { queryType: "TXT", entropy: 4.88, queryRateSec: 250 },
      },
      {
        eventId: "EVT-SCEN-103-B",
        timestamp: new Date(Date.now() - 20 * 60000).toISOString(),
        source: "Suricata NIDS",
        sourceType: "Network IDS",
        user: "system",
        ip: "10.0.10.22 -> 203.0.113.200",
        hostname: "GW-CORE-01",
        eventType: "Encrypted C2 Channel Establishment",
        description: "Outbound TLS flow with self-signed certificate subject mimicking legitimate CDN.",
        severity: "High",
        indicators: ["203.0.113.200"],
        metadata: { port: 443, ja3Fingerprint: "72a589da586844d7f0818ce684948eea" },
      },
    ],
    indicators: [
      {
        id: "TI-SCEN-103-1",
        indicator: "sync-telemetry-cache.info",
        type: "Domain",
        status: "Malicious (Synthetic)",
        confidence: 96,
        source: "Passive DNS Synthetic Intel",
        threatGroup: "Simulated Group FIN-APT",
        tags: ["dns-tunnel", "exfiltration"],
        notes: "Synthetic apex domain configured with wildcard NS records for data staging.",
      },
    ],
    actions: [
      {
        id: "ACT-SCEN-103-1",
        title: "Sinkhole sync-telemetry-cache.info DNS Resolution",
        actionType: "DNS Response Policy Zone (RPZ)",
        description: "Redirect all internal client lookups for the domain to 127.0.0.1.",
        riskLevel: "Low",
      },
    ],
  },
  {
    id: "scen-critical-vuln",
    name: "4. Critical Vulnerability Exploitation Attempt",
    category: "Vulnerability & Threat Management",
    description: "Proactive detection and virtual patching of an internet-facing Citrix Gateway vulnerability (CVE-2023-38606) undergoing active scanning.",
    incident: {
      incidentId: "INC-SCEN-104",
      title: "Perimeter Exploit Probes Targeting Citrix ADC Buffer Overflow",
      description: "External reconnaissance scanner executed crafted HTTP POST requests with excessive buffer headers against public NetScaler Gateway SRV-VPN-01.",
      severity: "High",
      riskScore: 79,
      status: "Investigating",
      affectedUser: "N/A",
      affectedAssets: ["SRV-VPN-01.corp.ext"],
      relatedEvents: ["EVT-SCEN-104-A", "EVT-SCEN-104-B"],
      indicators: ["CVE-2023-38606", "198.51.100.220"],
      timeline: [
        { time: "04:10:00", event: "Automated vulnerability scanner identified vulnerable build", source: "Qualys VM", severity: "Medium" },
        { time: "05:02:11", event: "Inbound malicious POST payload detected by WAF", source: "Cloudflare WAF", severity: "High" },
        { time: "05:05:00", event: "Virtual patch rule activated on perimeter WAF", source: "Cloudflare WAF", severity: "Low" },
      ],
      mitreTechniques: [
        { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access", status: "Confirmed" },
      ],
      recommendations: [
        "Deploy emergency firmware patch NS13.1-49.13 to SRV-VPN-01.",
        "Verify WAF virtual patch signature 100982 remains enforced.",
        "Conduct core dump forensic analysis on NetScaler memory partition.",
      ],
      riskBreakdown: {
        factors: [
          { name: "Public Internet Exposure", points: 35, reason: "Directly reachable SSL VPN gateway." },
          { name: "CVSS 9.8 Severity", points: 30, reason: "Remote code execution without authentication." },
          { name: "WAF Virtual Patch Defense", points: -15, reason: "Perimeter WAF blocked exploit payload in-flight." },
          { name: "Critical Gateway Importance", points: 29, reason: "Single point of failure for remote workforce." },
        ],
        totalScore: 79,
        maxScore: 100,
        explanation: "Risk score 79/100 reflects severe vulnerability mitigated temporarily by perimeter virtual patching.",
      },
    },
    events: [
      {
        eventId: "EVT-SCEN-104-A",
        timestamp: new Date(Date.now() - 60 * 60000).toISOString(),
        source: "Cloudflare WAF",
        sourceType: "Web Application Firewall",
        user: "anonymous",
        ip: "198.51.100.220",
        hostname: "vpn.enterprise-corp.com",
        eventType: "WAF Exploit Attempt Blocked",
        description: "Blocked unauthenticated POST request containing buffer overflow shellcode targeting Citrix ADC.",
        severity: "High",
        indicators: ["198.51.100.220", "CVE-2023-38606"],
        metadata: { ruleId: "941100", action: "BLOCK" },
      },
    ],
    indicators: [
      {
        id: "TI-SCEN-104-1",
        indicator: "198.51.100.220",
        type: "IP",
        status: "Malicious (Synthetic)",
        confidence: 91,
        source: "ThreatConnect Synthetic",
        threatGroup: "Mass Scanner Cluster",
        tags: ["exploit-scanner", "citrix-probe"],
        notes: "Automated vulnerability weaponization scanner IP.",
      },
    ],
    actions: [
      {
        id: "ACT-SCEN-104-1",
        title: "Block Originating Scanner IP 198.51.100.220",
        actionType: "Perimeter Firewall ACL",
        description: "Add IP to perimeter zero-trust drop list for 72 hours.",
        riskLevel: "Low",
      },
    ],
  },
  {
    id: "scen-suspicious-file",
    name: "5. Suspicious File Investigation",
    category: "Endpoint & Malware Defense",
    description: "Multi-factor endpoint investigation into a weaponized Microsoft Excel invoice macro executing an obfuscated VBScript loader.",
    incident: {
      incidentId: "INC-SCEN-105",
      title: "Weaponized Macro Attachment & Obfuscated VBScript Execution",
      description: "Employee downloaded Invoice_Sept2026.xlsm containing an XL4 macro that dropped an obfuscated script into %APPDATA%\\Local\\Temp.",
      severity: "High",
      riskScore: 76,
      status: "Investigating",
      affectedUser: "michael.scott@corp.internal",
      affectedAssets: ["WS-SALES-12.corp.local"],
      relatedEvents: ["EVT-SCEN-105-A", "EVT-SCEN-105-B"],
      indicators: ["SHA256:d8a2456e91f1b219c08d986518a45217bcde42...", "WS-SALES-12"],
      timeline: [
        { time: "11:20:00", event: "User downloaded Invoice_Sept2026.xlsm from external webmail", source: "Zscaler Proxy", severity: "Medium" },
        { time: "11:22:14", event: "Excel spawned wscript.exe executing dropped payload", source: "CrowdStrike EDR", severity: "High" },
        { time: "11:23:00", event: "EDR quarantined dropped binary before socket creation", source: "CrowdStrike EDR", severity: "Low" },
      ],
      mitreTechniques: [
        { id: "T1204.002", name: "Malicious File Execution", tactic: "Execution", status: "Confirmed" },
        { id: "T1059.005", name: "Visual Basic Script Interpreter", tactic: "Execution", status: "Confirmed" },
        { id: "T1027", name: "Obfuscated Files or Information", tactic: "Defense Evasion", status: "Confirmed" },
      ],
      recommendations: [
        "Enforce Group Policy blocking Office VBA macros from internet-downloaded documents (Mark of the Web).",
        "Perform full offline disk scan of WS-SALES-12.",
      ],
      riskBreakdown: {
        factors: [
          { name: "Malicious Macro Execution", points: 30, reason: "VBScript spawned by Excel." },
          { name: "Obfuscated Temp Dropper", points: 25, reason: "Randomly named payload in AppData folder." },
          { name: "Successful EDR Quarantine", points: -10, reason: "Host agent blocked execution before persistence." },
          { name: "Sales Subnet Blast Radius", points: 21, reason: "Machine connected to CRM internal network." },
        ],
        totalScore: 76,
        maxScore: 100,
        explanation: "Risk score 76/100: Macro executed but halted by automated EDR behavior detection.",
      },
    },
    events: [
      {
        eventId: "EVT-SCEN-105-A",
        timestamp: new Date(Date.now() - 40 * 60000).toISOString(),
        source: "CrowdStrike Falcon",
        sourceType: "Endpoint EDR",
        user: "michael.scott",
        ip: "10.0.6.45",
        hostname: "WS-SALES-12.corp.local",
        eventType: "Anomalous Child Process Creation",
        description: "Process excel.exe spawned wscript.exe with commandLine: wscript.exe %TEMP%\\update_svc.vbs",
        severity: "High",
        indicators: ["excel.exe", "wscript.exe"],
        metadata: { parentPid: 4912, childPid: 6814 },
      },
    ],
    indicators: [
      {
        id: "TI-SCEN-105-1",
        indicator: "d8a2456e91f1b219c08d986518a45217bcde42aa881029481948192837461928",
        type: "File Hash (SHA256)",
        status: "Malicious (Synthetic)",
        confidence: 95,
        source: "Synthetic Malware Sandbox",
        threatGroup: "Macro Loader Simulation",
        tags: ["vba-macro", "temp-dropper"],
        notes: "Synthetic malicious spreadsheet sample containing VBA dropper.",
      },
    ],
    actions: [
      {
        id: "ACT-SCEN-105-1",
        title: "Quarantine File update_svc.vbs across all Endpoints",
        actionType: "Global Hash Quarantine",
        description: "Broadcast SHA256 hash block rule to all corporate workstations.",
        riskLevel: "Low",
      },
    ],
  },
  {
    id: "scen-cloud-misconfig",
    name: "6. Cloud Infrastructure Misconfiguration",
    category: "Cloud Security Posture",
    description: "Critical AWS cloud posture alert involving an open S3 production bucket and over-privileged cross-account IAM role assumption.",
    incident: {
      incidentId: "INC-SCEN-106",
      title: "Public S3 Bucket Policy & Overprivileged IAM Cross-Account Role",
      description: "AWS CloudTrail captured PutBucketPolicy granting public unauthenticated Read access to production archive bucket, followed by AssumeRole from external AWS account.",
      severity: "High",
      riskScore: 84,
      status: "Investigating",
      affectedUser: "automation-sync-service",
      affectedAssets: ["arn:aws:s3:::financial-reports-archive-prod", "arn:aws:iam::123456789012:role/DeployerRole"],
      relatedEvents: ["EVT-SCEN-106-A", "EVT-SCEN-106-B"],
      indicators: ["arn:aws:s3:::financial-reports-archive-prod", "203.0.113.89"],
      timeline: [
        { time: "14:02:10", event: "PutBucketPolicy executed by service account", source: "AWS CloudTrail", severity: "High" },
        { time: "14:08:22", event: "AssumeRole request from unknown AWS Account 998877665544", source: "AWS CloudTrail", severity: "Critical" },
        { time: "14:10:00", event: "AWS Security Hub CSPM Compliance Alarm", source: "AWS Security Hub", severity: "High" },
      ],
      mitreTechniques: [
        { id: "T1530", name: "Data from Cloud Storage Object", tactic: "Collection", status: "Confirmed" },
        { id: "T1098", name: "Account Manipulation", tactic: "Persistence", status: "Confirmed" },
      ],
      recommendations: [
        "Enable S3 Account-level Block Public Access.",
        "Remove external Principal 998877665544 from IAM trust policy.",
        "Audit S3 access access logs for unauthorized object downloads.",
      ],
      riskBreakdown: {
        factors: [
          { name: "Public Data Exposure", points: 35, reason: "Bucket contains encrypted corporate financial backups." },
          { name: "Cross-Account Trust Exploitation", points: 28, reason: "External AWS account assumed administrative role." },
          { name: "Non-Compliance Penalty", points: 21, reason: "Breaches SOC 2 and ISO 27001 data isolation controls." },
        ],
        totalScore: 84,
        maxScore: 100,
        explanation: "Risk score 84/100: Critical cloud data exposure requiring instantaneous policy enforcement.",
      },
    },
    events: [
      {
        eventId: "EVT-SCEN-106-A",
        timestamp: new Date(Date.now() - 25 * 60000).toISOString(),
        source: "AWS CloudTrail",
        sourceType: "Cloud Audit",
        user: "automation-sync-service",
        ip: "203.0.113.89",
        hostname: "aws-s3-prod",
        eventType: "PutBucketPolicy (Public Read Granted)",
        description: "Modified policy on financial-reports-archive-prod granting Principal: * permission s3:GetObject.",
        severity: "Critical",
        indicators: ["arn:aws:s3:::financial-reports-archive-prod"],
        metadata: { effect: "Allow", principal: "*" },
      },
      {
        eventId: "EVT-SCEN-106-B",
        timestamp: new Date(Date.now() - 18 * 60000).toISOString(),
        source: "AWS CloudTrail",
        sourceType: "Cloud Audit",
        user: "arn:aws:iam::998877665544:root",
        ip: "203.0.113.89",
        hostname: "aws-iam-sts",
        eventType: "sts:AssumeRole Unauthorized External Account",
        description: "Unknown external AWS account assumed DeployerRole from residential IP.",
        severity: "Critical",
        indicators: ["203.0.113.89"],
        metadata: { roleArn: "arn:aws:iam::123456789012:role/DeployerRole" },
      },
    ],
    indicators: [
      {
        id: "TI-SCEN-106-1",
        indicator: "203.0.113.89",
        type: "IP",
        status: "Suspicious (Synthetic)",
        confidence: 82,
        source: "AWS GuardDuty Synthetic",
        threatGroup: "Cloud Reconnaissance",
        tags: ["vpn-exit", "cloudtrail-anomaly"],
        notes: "Synthetic IP tied to anomalous AWS API administrative invocations.",
      },
    ],
    actions: [
      {
        id: "ACT-SCEN-106-1",
        title: "Apply Account-wide S3 Block Public Access",
        actionType: "Cloud Security Remediation",
        description: "Enforce PutAccountPublicAccessBlock across current AWS region.",
        riskLevel: "Medium",
      },
      {
        id: "ACT-SCEN-106-2",
        title: "Revoke IAM Trust Policy for Unknown Account",
        actionType: "IAM Policy Lockdown",
        description: "Remove 998877665544 from assume role trust relationship.",
        riskLevel: "High",
      },
    ],
  },
];

export async function loadScenario(scenarioId: string) {
  const scenario = DEMO_SCENARIOS.find((s) => s.id === scenarioId);
  if (!scenario) {
    throw new Error(`Scenario ${scenarioId} not found`);
  }

  // Insert or replace incident
  const inc = scenario.incident;
  await db.execute({
    sql: `INSERT OR REPLACE INTO incidents (incidentId, title, description, severity, riskScore, status, affectedUser, affectedAssets, relatedEvents, indicators, timeline, mitreTechniques, recommendations, riskBreakdown, createdAt, updatedAt)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    args: [
      inc.incidentId,
      inc.title,
      inc.description,
      inc.severity,
      inc.riskScore,
      inc.status,
      inc.affectedUser,
      JSON.stringify(inc.affectedAssets),
      JSON.stringify(inc.relatedEvents),
      JSON.stringify(inc.indicators),
      JSON.stringify(inc.timeline),
      JSON.stringify(inc.mitreTechniques),
      JSON.stringify(inc.recommendations),
      JSON.stringify(inc.riskBreakdown),
      new Date(Date.now() - 40 * 60000).toISOString(),
      new Date().toISOString(),
    ],
  });

  // Insert events
  for (const ev of scenario.events) {
    await db.execute({
      sql: `INSERT OR REPLACE INTO security_events (eventId, timestamp, source, sourceType, user, ip, hostname, eventType, description, severity, indicators, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [
        ev.eventId,
        ev.timestamp,
        ev.source,
        ev.sourceType,
        ev.user,
        ev.ip,
        ev.hostname,
        ev.eventType,
        ev.description,
        ev.severity,
        JSON.stringify(ev.indicators),
        JSON.stringify(ev.metadata),
      ],
    });
  }

  // Insert indicators
  for (const ti of scenario.indicators) {
    await db.execute({
      sql: `INSERT OR REPLACE INTO threat_intel (id, indicator, type, status, confidence, firstSeen, lastSeen, source, threatGroup, tags, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [
        ti.id,
        ti.indicator,
        ti.type,
        ti.status,
        ti.confidence,
        new Date(Date.now() - 7 * 86400000).toISOString(),
        new Date().toISOString(),
        ti.source,
        ti.threatGroup,
        JSON.stringify(ti.tags),
        ti.notes,
      ],
    });
  }

  // Insert actions
  for (const act of scenario.actions) {
    await db.execute({
      sql: `INSERT OR REPLACE INTO response_actions (id, incidentId, title, actionType, description, recommendedBy, riskLevel, status, decidedBy, decidedAt, justification, createdAt)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [
        act.id,
        inc.incidentId,
        act.title,
        act.actionType,
        act.description,
        "CyberSentinel Autonomous Engine",
        act.riskLevel,
        "PENDING",
        null,
        null,
        null,
        new Date().toISOString(),
      ],
    });
  }

  // Insert audit log
  await db.execute({
    sql: `INSERT INTO audit_logs (id, timestamp, userAction, actionType, incidentId, aiRecommendation, analystDecision, details)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    args: [
      `AUD-${Date.now().toString().slice(-4)}`,
      new Date().toISOString(),
      `Demo Scenario Loaded: ${scenario.name}`,
      "Scenario Activation",
      inc.incidentId,
      `Autonomous correlation generated incident ${inc.incidentId} with risk score ${inc.riskScore}/100.`,
      "Activated via Synthetic Demo Engine",
      `Populated ${scenario.events.length} security events, ${scenario.indicators.length} threat indicators, and ${scenario.actions.length} response recommendations.`,
    ],
  });

  return scenario;
}
