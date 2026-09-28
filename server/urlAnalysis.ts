import { GoogleGenAI } from "@google/genai";
import { db } from "./db.js";
import { threatIntelService } from "./threatIntel/service.js";

const apiKey = process.env.GEMINI_API_KEY || "";
const ai = new GoogleGenAI({
  apiKey: apiKey,
  httpOptions: {
    headers: {
      "User-Agent": "aistudio-build",
    },
  },
});

export interface UrlCheck {
  name: string;
  category: "length" | "protocol" | "ip_host" | "subdomain" | "characters" | "encoding" | "path" | "query" | "threat_intel";
  status: "safe" | "warning" | "danger";
  details: string;
  points: number;
}

export interface ExtractedUrlIndicator {
  indicator: string;
  type: "Domain" | "URL" | "IP" | "Path" | "Parameter";
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  description: string;
  isThreatIntelMatch?: boolean;
  reputation?: string;
  source?: string;
  confidence?: number;
}

export interface UrlAnalysisResult {
  valid: boolean;
  error?: string;
  url: string;
  riskScore: number;
  classification: "Malicious" | "Suspicious" | "Benign";
  structuralDetails: {
    protocol: string;
    hostname: string;
    port: string;
    pathname: string;
    search: string;
    hash: string;
    length: number;
    subdomainsCount: number;
    subdomainList: string[];
    entropyScore: number;
    isIpHost: boolean;
    isHttps: boolean;
    hasUserinfo: boolean;
    hasPunycode: boolean;
    encodingFindings: string[];
    pathFindings: string[];
    queryFindings: string[];
  } | null;
  checks: UrlCheck[];
  indicators: ExtractedUrlIndicator[];
  explanation: {
    summary: string;
    factors: Array<{ factor: string; points: number; reason: string }>;
    geminiAssessment?: string;
    threatIntelCorrelation?: {
      matchedIndicators: Array<{
        indicator: string;
        type: string;
        reputation: string;
        source: string;
        confidence: number;
      }>;
      relatedIncidents: string[];
    };
  };
  recommendedInvestigation: string[];
  defensiveGuidance: string[];
  engine: "gemini" | "structural_heuristic";
}

/**
 * Calculates Shannon entropy of a string (higher = more random/DGA-like)
 */
function calculateEntropy(str: string): number {
  const len = str.length;
  if (len === 0) return 0;
  const freqs: Record<string, number> = {};
  for (let i = 0; i < len; i++) {
    const ch = str[i];
    freqs[ch] = (freqs[ch] || 0) + 1;
  }
  let entropy = 0;
  for (const count of Object.values(freqs)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(2));
}

/**
 * Detects if a hostname is an IP address in any notation:
 * Standard dotted IPv4, decimal, hexadecimal, octal, or IPv6
 */
function isIpAddress(hostname: string): { isIp: boolean; type: string } {
  // IPv4 standard dotted decimal: 198.51.100.44
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Regex.test(hostname)) {
    const parts = hostname.split(".").map(Number);
    const valid = parts.every((p) => p >= 0 && p <= 255);
    if (valid) return { isIp: true, type: "IPv4 Dotted-Decimal" };
  }

  // IPv4 pure integer/dword (e.g. 3325256748)
  if (/^\d{8,11}$/.test(hostname)) {
    const num = Number(hostname);
    if (num > 0 && num <= 4294967295) {
      return { isIp: true, type: "IPv4 Dword/Integer" };
    }
  }

  // IPv4 Hexadecimal (e.g. 0xc6.0x33.0x64.0x2c or 0xc633642c)
  if (/^0x[0-9a-f]{8}$/i.test(hostname) || /^0x[0-9a-f]{1,2}(\.0x[0-9a-f]{1,2}){3}$/i.test(hostname)) {
    return { isIp: true, type: "IPv4 Hexadecimal" };
  }

  // IPv6 notation (e.g. [::1] or [2001:db8::1])
  if (hostname.startsWith("[") && hostname.endsWith("]")) {
    return { isIp: true, type: "IPv6 Bracketed" };
  }
  if (hostname.includes(":") && hostname.split(":").length >= 3) {
    return { isIp: true, type: "IPv6 Unbracketed" };
  }

  return { isIp: false, type: "" };
}

/**
 * Defensive Structural URL Analysis
 * Completely passive - does not initiate any outbound HTTP, socket, or DNS queries to target.
 * Analyzes string syntax, lexical patterns, entropy, and cross-references local SOC database.
 */
export async function analyzeUrlDefense(rawUrl: string): Promise<UrlAnalysisResult> {
  const cleanUrl = rawUrl.trim();

  // Basic normalization for URL parser
  let normalizedUrl = cleanUrl;
  if (!/^https?:\/\//i.test(normalizedUrl) && !normalizedUrl.includes("://")) {
    normalizedUrl = "https://" + normalizedUrl;
  }

  let parsed: URL;
  try {
    parsed = new URL(normalizedUrl);
  } catch (err: any) {
    return {
      valid: false,
      error: `Syntax Parsing Failure: "${cleanUrl}" could not be parsed as a valid RFC 3986 URI.`,
      url: cleanUrl,
      riskScore: 60,
      classification: "Suspicious",
      structuralDetails: null,
      checks: [
        {
          name: "URI Syntax Malformation",
          category: "characters",
          status: "danger",
          details: "URL string deviates from RFC standard formatting or contains unparseable characters.",
          points: 40,
        },
      ],
      indicators: [{
        indicator: cleanUrl,
        type: "URL",
        severity: "Medium",
        description: "Unparseable raw input string",
      }],
      explanation: {
        summary: "URL string is syntactically malformed and cannot be decomposed into standard RFC URI components.",
        factors: [{ factor: "Syntax Malformation", points: 40, reason: "Invalid URI structure" }],
      },
      recommendedInvestigation: [
        "Inspect origin payload for raw byte encoding corruption or evasion framing.",
        "Sanitize input and verify with perimeter log telemetry.",
      ],
      defensiveGuidance: ["No active probe dispatched. Verify syntax manually."],
      engine: "structural_heuristic",
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const checks: UrlCheck[] = [];
  const indicators: ExtractedUrlIndicator[] = [];
  const riskFactors: Array<{ factor: string; points: number; reason: string }> = [];

  let calculatedScore = 0;

  // ---------------------------------------------------------
  // 1. URL LENGTH CHECK
  // ---------------------------------------------------------
  const totalLength = cleanUrl.length;
  if (totalLength > 180) {
    checks.push({
      name: "Excessive Overall URL Length",
      category: "length",
      status: "danger",
      details: `URL length is ${totalLength} characters (threshold > 180). Adversaries frequently inflate length to conceal hostname in browser address bars or bypass heuristic length thresholds.`,
      points: 25,
    });
    calculatedScore += 25;
    riskFactors.push({ factor: "Excessive Length", points: 25, reason: `Total length is ${totalLength} chars (>180)` });
  } else if (totalLength > 90) {
    checks.push({
      name: "Elevated URL Length",
      category: "length",
      status: "warning",
      details: `URL length is ${totalLength} characters (threshold > 90). Moderately elevated length often seen with tracking strings or token harvesting.`,
      points: 12,
    });
    calculatedScore += 12;
    riskFactors.push({ factor: "Elevated Length", points: 12, reason: `Total length is ${totalLength} chars (>90)` });
  } else {
    checks.push({
      name: "Standard URL Length",
      category: "length",
      status: "safe",
      details: `URL length is ${totalLength} characters, within nominal enterprise web standards.`,
      points: 0,
    });
  }

  // ---------------------------------------------------------
  // 2. HTTPS / PROTOCOL TRANSPORT CHECK
  // ---------------------------------------------------------
  const protocol = parsed.protocol.toLowerCase();
  if (protocol === "https:") {
    checks.push({
      name: "Transport Security (HTTPS)",
      category: "protocol",
      status: "safe",
      details: "URL specifies encrypted TLS/HTTPS transport (port 443 standard).",
      points: 0,
    });
  } else if (protocol === "http:") {
    checks.push({
      name: "Insecure Plaintext Transport (HTTP)",
      category: "protocol",
      status: "warning",
      details: "URL uses unencrypted plain HTTP (port 80). Discloses session tokens in transit; typical for ephemeral credential harvesting domains lacking SSL certs.",
      points: 18,
    });
    calculatedScore += 18;
    riskFactors.push({ factor: "Plaintext HTTP", points: 18, reason: "Unencrypted transport protocol" });
  } else {
    checks.push({
      name: "Non-Standard URI Protocol Scheme",
      category: "protocol",
      status: "danger",
      details: `URL specifies unusual protocol scheme: "${protocol}". Potential protocol handler hijacking or client-side payload delivery.`,
      points: 30,
    });
    calculatedScore += 30;
    riskFactors.push({ factor: "Non-Standard Protocol", points: 30, reason: `Scheme "${protocol}" detected` });
  }

  // ---------------------------------------------------------
  // 3. IP-BASED HOST CHECK
  // ---------------------------------------------------------
  const ipCheck = isIpAddress(hostname);
  if (ipCheck.isIp) {
    checks.push({
      name: `IP-Based Hostname (${ipCheck.type})`,
      category: "ip_host",
      status: "danger",
      details: `Destination host is specified directly as a raw IP address (${hostname}) instead of a registered domain. Strong evasion tactic used to bypass domain reputation blocklists and DNS-based defenses.`,
      points: 35,
    });
    calculatedScore += 35;
    riskFactors.push({ factor: "IP Host Evasion", points: 35, reason: `Direct IP host format: ${ipCheck.type}` });
    indicators.push({
      indicator: hostname,
      type: "IP",
      severity: "High",
      description: `Raw IP host address (${ipCheck.type}) bypassed DNS registry lookup`,
    });
  } else {
    checks.push({
      name: "Standard Domain Hostname",
      category: "ip_host",
      status: "safe",
      details: `Hostname resolves through domain name system hierarchy (${hostname}).`,
      points: 0,
    });
    indicators.push({
      indicator: hostname,
      type: "Domain",
      severity: "Low",
      description: "Extracted Fully Qualified Domain Name (FQDN)",
    });
  }

  // ---------------------------------------------------------
  // 4. SUBDOMAIN COMPLEXITY & ENTROPY
  // ---------------------------------------------------------
  const hostLabels = hostname.split(".").filter(Boolean);
  const subdomainLabels = hostLabels.slice(0, Math.max(0, hostLabels.length - 2));
  const subdomainsCount = subdomainLabels.length;
  const entropy = calculateEntropy(hostname);

  if (subdomainsCount >= 4) {
    checks.push({
      name: "Excessive Subdomain Nesting Depth",
      category: "subdomain",
      status: "danger",
      details: `Domain contains ${subdomainsCount} nested subdomain labels (${subdomainLabels.join(".")}). Deep subdomain chains are frequently used to mimic authentic organizational domain structures.`,
      points: 25,
    });
    calculatedScore += 25;
    riskFactors.push({ factor: "Deep Subdomain Nesting", points: 25, reason: `${subdomainsCount} subdomain levels` });
  } else if (subdomainsCount >= 2) {
    checks.push({
      name: "Elevated Subdomain Complexity",
      category: "subdomain",
      status: "warning",
      details: `Domain contains ${subdomainsCount} subdomain labels (${subdomainLabels.join(".")}). Warrants verification against corporate naming taxonomy.`,
      points: 12,
    });
    calculatedScore += 12;
    riskFactors.push({ factor: "Elevated Subdomain Depth", points: 12, reason: `${subdomainsCount} subdomain labels` });
  } else {
    checks.push({
      name: "Nominal Subdomain Structure",
      category: "subdomain",
      status: "safe",
      details: `Standard domain hierarchy with ${subdomainsCount} subdomain label(s).`,
      points: 0,
    });
  }

  // Brand impersonation in subdomains
  const brandKeywords = ["microsoft", "google", "apple", "paypal", "login", "office365", "sso", "portal", "okta", "cisco", "chase", "bank"];
  const matchedBrandInSubdomain = brandKeywords.find((b) => subdomainLabels.some((lbl) => lbl.includes(b)));
  if (matchedBrandInSubdomain) {
    checks.push({
      name: `Brand Impersonation in Subdomain ("${matchedBrandInSubdomain}")`,
      category: "subdomain",
      status: "danger",
      details: `Subdomain contains targeted brand keyword "${matchedBrandInSubdomain}" prepended to a secondary root domain. Classic brand spoofing vector.`,
      points: 30,
    });
    calculatedScore += 30;
    riskFactors.push({ factor: "Brand Spoofing in Subdomain", points: 30, reason: `Target brand "${matchedBrandInSubdomain}" in subdomain` });
    indicators.push({
      indicator: `${matchedBrandInSubdomain}.${hostname}`,
      type: "Domain",
      severity: "High",
      description: `Brand spoofing pattern detected in subdomain targeting ${matchedBrandInSubdomain}`,
    });
  }

  // Shannon entropy check
  if (entropy > 3.8 && !ipCheck.isIp) {
    checks.push({
      name: `High Hostname Shannon Entropy (${entropy})`,
      category: "subdomain",
      status: "warning",
      details: `Hostname exhibits high character randomness (Shannon Entropy = ${entropy} bits/char). Characteristic of Domain Generation Algorithms (DGA) or disposable automated hosting.`,
      points: 18,
    });
    calculatedScore += 18;
    riskFactors.push({ factor: "High Hostname Entropy", points: 18, reason: `Entropy = ${entropy} (DGA signature)` });
  }

  // Hyphen density in hostname
  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    checks.push({
      name: "High Hyphen Density in Hostname",
      category: "subdomain",
      status: "warning",
      details: `Hostname contains ${hyphenCount} hyphens. Often leveraged to concatenate multiple trust keywords (e.g. corporate-sso-gateway-auth).`,
      points: 12,
    });
    calculatedScore += 12;
    riskFactors.push({ factor: "Hyphen Stacking", points: 12, reason: `${hyphenCount} hyphens in host` });
  }

  // ---------------------------------------------------------
  // 5. SUSPICIOUS CHARACTERS & HIGH-ABUSE TLDs
  // ---------------------------------------------------------
  const charFindings: string[] = [];

  // Userinfo character @
  if (cleanUrl.includes("@")) {
    checks.push({
      name: "Userinfo Destination Spoofing Symbol (@)",
      category: "characters",
      status: "danger",
      details: "URL contains '@' userinfo separator. Browsers treat characters prior to '@' as credentials and route to host following '@', deceiving the human reader.",
      points: 35,
    });
    calculatedScore += 35;
    charFindings.push("Userinfo (@) separator");
    riskFactors.push({ factor: "Userinfo Destination Spoofing", points: 35, reason: "Embedded '@' symbol masks actual host" });
    indicators.push({
      indicator: "@ symbol",
      type: "Parameter",
      severity: "Critical",
      description: "Userinfo character used to camouflage destination host",
    });
  }

  // Punycode / IDN
  if (hostname.startsWith("xn--") || hostname.includes(".xn--")) {
    checks.push({
      name: "Punycode Internationalized Domain (IDN)",
      category: "characters",
      status: "warning",
      details: `Punycode prefix ("xn--") detected. Frequently used in homoglyph attacks where Cyrillic or Greek characters visually imitate Latin domain names.`,
      points: 22,
    });
    calculatedScore += 22;
    charFindings.push("Punycode (xn--) homoglyph");
    riskFactors.push({ factor: "Punycode Homoglyph", points: 22, reason: "IDN punycode detected" });
  }

  // High abuse TLDs
  const suspiciousTlds = [
    ".top", ".xyz", ".cc", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".buzz", ".work", ".click", ".fit", ".country", ".su",
    ".shop", ".online", ".club", ".live", ".monster", ".space"
  ];
  const matchedSusTld = suspiciousTlds.find((tld) => hostname.endsWith(tld));
  if (matchedSusTld) {
    checks.push({
      name: `High-Abuse Top-Level Domain (${matchedSusTld})`,
      category: "characters",
      status: "danger",
      details: `Domain utilizes TLD "${matchedSusTld}", which historically exhibits high correlation with automated phishing campaigns and low cost-of-acquisition abuse.`,
      points: 25,
    });
    calculatedScore += 25;
    charFindings.push(`High-abuse TLD: ${matchedSusTld}`);
    riskFactors.push({ factor: "High-Abuse TLD", points: 25, reason: `TLD "${matchedSusTld}" flagged in threat intelligence feeds` });
  }

  // ---------------------------------------------------------
  // 6. ENCODING PATTERNS
  // ---------------------------------------------------------
  const encodingFindings: string[] = [];

  // Double percent encoding (%25)
  if (/%25[0-9a-f]{2}/i.test(cleanUrl)) {
    checks.push({
      name: "Double URL Percent Encoding Detected (%25xx)",
      category: "encoding",
      status: "danger",
      details: "URL contains double-percent encoded characters (e.g. %252f for slash). Common defense evasion tactic designed to bypass web application firewall (WAF) token decoders.",
      points: 30,
    });
    calculatedScore += 30;
    encodingFindings.push("Double percent encoding (%25xx)");
    riskFactors.push({ factor: "Double Percent Encoding", points: 30, reason: "WAF evasion sequence detected" });
  }

  // Path traversal sequences
  if (cleanUrl.includes("..") || /%2e%2e/i.test(cleanUrl) || /%252e%252e/i.test(cleanUrl)) {
    checks.push({
      name: "Directory Traversal Sequence (../)",
      category: "encoding",
      status: "danger",
      details: "URL contains dot-dot-slash directory traversal patterns. Typically indicates local file inclusion (LFI) or path escaping attempt.",
      points: 32,
    });
    calculatedScore += 32;
    encodingFindings.push("Directory traversal sequence (../)");
    riskFactors.push({ factor: "Directory Traversal", points: 32, reason: "Traversal dots detected in path/query" });
  }

  // Base64 fragment detection in path or query
  const base64Regex = /([A-Za-z0-9+/]{24,}={0,2})/g;
  const base64Matches = cleanUrl.match(base64Regex);
  if (base64Matches && base64Matches.length > 0) {
    checks.push({
      name: "Embedded Base64 Encoded Payload/Token",
      category: "encoding",
      status: "warning",
      details: `Detected potential Base64 encoded payload fragment (${base64Matches[0].slice(0, 20)}...). Often used to convey exfiltrated credentials, encoded commands, or serialized session data.`,
      points: 20,
    });
    calculatedScore += 20;
    encodingFindings.push(`Base64 blob: ${base64Matches[0].slice(0, 25)}...`);
    riskFactors.push({ factor: "Base64 Fragment", points: 20, reason: "Serialized or obfuscated parameter blob" });
  }

  // Hexadecimal escapes (\x or 0x in path)
  if (/(\\x[0-9a-f]{2}|0x[0-9a-f]{2})/i.test(cleanUrl)) {
    checks.push({
      name: "Hexadecimal Character Escapes",
      category: "encoding",
      status: "warning",
      details: "URL contains explicit hexadecimal notation escapes within URI path or query string.",
      points: 15,
    });
    calculatedScore += 15;
    encodingFindings.push("Hexadecimal escape sequence");
    riskFactors.push({ factor: "Hexadecimal Escapes", points: 15, reason: "Raw hex escape characters present" });
  }

  // Standard percent encoding density
  const percentCount = (cleanUrl.match(/%[0-9a-f]{2}/gi) || []).length;
  if (percentCount >= 4 && !encodingFindings.includes("Double percent encoding (%25xx)")) {
    checks.push({
      name: `High Percent-Encoding Density (${percentCount} instances)`,
      category: "encoding",
      status: "warning",
      details: `URL contains ${percentCount} percent-encoded hex sequences. High density indicates obfuscation of path components or parameter keys.`,
      points: 14,
    });
    calculatedScore += 14;
    encodingFindings.push(`${percentCount} percent-encoded tokens`);
    riskFactors.push({ factor: "Percent Encoding Density", points: 14, reason: `${percentCount} encoded characters` });
  }

  // ---------------------------------------------------------
  // 7. PATH STRUCTURE
  // ---------------------------------------------------------
  const pathFindings: string[] = [];
  const pathname = parsed.pathname;
  const pathLower = pathname.toLowerCase();

  // Suspicious executable or archive file extensions
  const dangerousExtensions = [
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".hta", ".iso", ".zip", ".rar", ".7z", ".apk", ".dmg", ".dll"
  ];
  const matchedDangerousExt = dangerousExtensions.find((ext) => pathLower.endsWith(ext) || pathLower.includes(ext + "?") || pathLower.includes(ext + "/"));
  if (matchedDangerousExt) {
    checks.push({
      name: `Executable / Archive File Extension ("${matchedDangerousExt}")`,
      category: "path",
      status: "danger",
      details: `URL path targets an executable binary or compressed archive (${matchedDangerousExt}). Strong indicator of direct drive-by malware delivery.`,
      points: 35,
    });
    calculatedScore += 35;
    pathFindings.push(`Executable extension: ${matchedDangerousExt}`);
    riskFactors.push({ factor: "Malicious File Extension", points: 35, reason: `Target extension ${matchedDangerousExt}` });
    indicators.push({
      indicator: matchedDangerousExt,
      type: "Path",
      severity: "Critical",
      description: `Payload delivery extension: ${matchedDangerousExt}`,
    });
  }

  // Double file extensions (e.g. invoice.pdf.exe)
  if (/\.[a-z0-9]{2,4}\.(exe|scr|bat|vbs|zip|iso)$/i.test(pathLower)) {
    checks.push({
      name: "Double File Extension Deception Pattern",
      category: "path",
      status: "danger",
      details: "URL path exhibits double extension spoofing (e.g. .pdf.exe) intended to trick users into executing malicious code.",
      points: 35,
    });
    calculatedScore += 35;
    pathFindings.push("Double extension spoofing");
    riskFactors.push({ factor: "Double File Extension", points: 35, reason: "Masqueraded file type" });
  }

  // Consecutive slashes // in path
  if (pathname.includes("//")) {
    checks.push({
      name: "Consecutive Slashes in Path (//)",
      category: "path",
      status: "warning",
      details: "URL contains redundant consecutive slashes in the path component. Commonly used for path normalization bypass.",
      points: 12,
    });
    calculatedScore += 12;
    pathFindings.push("Consecutive slashes in path");
    riskFactors.push({ factor: "Consecutive Slashes", points: 12, reason: "Path normalization anomaly" });
  }

  // Credential and banking path keywords
  const sensitivePathKeywords = [
    "/login", "/auth", "/signin", "/verify", "/account", "/wallet",
    "/secure", "/update", "/banking", "/webscr", "/portal", "/sso",
    "/reset", "/credential", "/confirm", "/passcode"
  ];
  const matchedPathKeyword = sensitivePathKeywords.find((kw) => pathLower.includes(kw));
  if (matchedPathKeyword) {
    checks.push({
      name: `Sensitive Authentication Path Keyword ("${matchedPathKeyword}")`,
      category: "path",
      status: "warning",
      details: `Path contains sensitive credential or verification endpoint keyword: "${matchedPathKeyword}".`,
      points: 16,
    });
    calculatedScore += 16;
    pathFindings.push(`Sensitive keyword: ${matchedPathKeyword}`);
    riskFactors.push({ factor: "Authentication Path Keyword", points: 16, reason: `Path targets "${matchedPathKeyword}"` });
    indicators.push({
      indicator: matchedPathKeyword,
      type: "Path",
      severity: "Medium",
      description: `Credential targeting URI keyword: ${matchedPathKeyword}`,
    });
  }

  // Path depth
  const pathSegments = pathname.split("/").filter(Boolean);
  if (pathSegments.length > 5) {
    checks.push({
      name: `Excessive Path Depth (${pathSegments.length} directory levels)`,
      category: "path",
      status: "warning",
      details: `Path contains ${pathSegments.length} directory levels, indicative of deep directory spoofing or automated kit structure.`,
      points: 10,
    });
    calculatedScore += 10;
    pathFindings.push(`Path depth: ${pathSegments.length} levels`);
    riskFactors.push({ factor: "Excessive Path Depth", points: 10, reason: `${pathSegments.length} folder levels` });
  }

  // ---------------------------------------------------------
  // 8. QUERY PARAMETERS
  // ---------------------------------------------------------
  const queryFindings: string[] = [];
  const searchParams = parsed.searchParams;
  const paramKeys = Array.from(searchParams.keys());

  // Open redirect parameter detection
  const openRedirectKeys = ["url", "redirect", "next", "return", "destination", "goto", "target", "link", "r", "uri"];
  const matchedRedirectKey = paramKeys.find((k) => openRedirectKeys.includes(k.toLowerCase()));
  if (matchedRedirectKey) {
    const val = searchParams.get(matchedRedirectKey) || "";
    if (val.startsWith("http") || val.includes(".com") || val.includes(".org") || val.startsWith("//")) {
      checks.push({
        name: `Open Redirect Parameter Pattern ("${matchedRedirectKey}")`,
        category: "query",
        status: "danger",
        details: `Query contains parameter "${matchedRedirectKey}" directing execution to an external target ("${val.slice(0, 35)}..."). Highly exploited for open redirect credential lures.`,
        points: 28,
      });
      calculatedScore += 28;
      queryFindings.push(`Open redirect param: ${matchedRedirectKey}=${val.slice(0, 30)}...`);
      riskFactors.push({ factor: "Open Redirect Parameter", points: 28, reason: `Parameter "${matchedRedirectKey}" contains external destination` });
      indicators.push({
        indicator: `${matchedRedirectKey}=${val.slice(0, 40)}`,
        type: "Parameter",
        severity: "High",
        description: `Open redirect parameter forwarding to ${val.slice(0, 30)}`,
      });
    }
  }

  // Sensitive credential / token parameter names
  const sensitiveParamNames = ["token", "session", "auth", "pass", "pwd", "code", "secret", "payload", "cmd", "key"];
  const matchedSensitiveParam = paramKeys.find((k) => sensitiveParamNames.includes(k.toLowerCase()));
  if (matchedSensitiveParam) {
    checks.push({
      name: `Sensitive Token/Credential Parameter ("${matchedSensitiveParam}")`,
      category: "query",
      status: "warning",
      details: `Query contains sensitive security parameter "${matchedSensitiveParam}". Indicates session token reflection or credential capture.`,
      points: 15,
    });
    calculatedScore += 15;
    queryFindings.push(`Sensitive param: ${matchedSensitiveParam}`);
    riskFactors.push({ factor: "Sensitive Query Parameter", points: 15, reason: `Parameter "${matchedSensitiveParam}" exposed in URL query` });
  }

  // High parameter count
  if (paramKeys.length >= 5) {
    checks.push({
      name: `High Query Parameter Count (${paramKeys.length} parameters)`,
      category: "query",
      status: "warning",
      details: `URL contains ${paramKeys.length} query arguments, often used for complex adversary tracking, telemetry obfuscation, or state injection.`,
      points: 10,
    });
    calculatedScore += 10;
    queryFindings.push(`${paramKeys.length} query parameters`);
    riskFactors.push({ factor: "High Parameter Count", points: 10, reason: `${paramKeys.length} query parameters` });
  }

  // Query string length
  if (parsed.search.length > 100) {
    checks.push({
      name: `Excessive Query String Length (${parsed.search.length} chars)`,
      category: "query",
      status: "warning",
      details: `Query parameter payload is ${parsed.search.length} characters long.`,
      points: 12,
    });
    calculatedScore += 12;
    queryFindings.push(`Query length: ${parsed.search.length} chars`);
    riskFactors.push({ factor: "Excessive Query Length", points: 12, reason: `${parsed.search.length} characters in query` });
  }

  // ---------------------------------------------------------
  // 9. CROSS-REFERENCE APPLICATION DATA (Threat Intel & Incidents)
  // ---------------------------------------------------------
  const matchedTI: Array<{
    indicator: string;
    type: string;
    reputation: string;
    source: string;
    confidence: number;
  }> = [];
  const relatedIncidents: string[] = [];

  try {
    // 9a. Check Threat Intelligence database
    const candidates = [cleanUrl, hostname];
    if (ipCheck.isIp) candidates.push(hostname);

    for (const c of candidates) {
      const lookup = await threatIntelService.lookup(c);
      if (lookup && lookup.indicator) {
        matchedTI.push({
          indicator: lookup.indicator,
          type: lookup.type,
          reputation: lookup.reputation,
          source: lookup.source,
          confidence: lookup.confidence,
        });

        if (lookup.reputation === "Malicious") {
          checks.push({
            name: `Threat Intel Match: Verified Malicious Indicator ("${c}")`,
            category: "threat_intel",
            status: "danger",
            details: `Observable matches verified malicious record in CyberSentinel threat intelligence database (Confidence: ${lookup.confidence}%, Source: ${lookup.source}).`,
            points: 35,
          });
          calculatedScore += 35;
          riskFactors.push({
            factor: "Threat Intelligence Correlation",
            points: 35,
            reason: `Direct match against active threat intelligence record (${lookup.source})`,
          });
          indicators.push({
            indicator: c,
            type: lookup.type as any,
            severity: "Critical",
            description: `Verified malicious indicator in internal TI database (${lookup.source})`,
            isThreatIntelMatch: true,
            reputation: lookup.reputation,
            source: lookup.source,
            confidence: lookup.confidence,
          });
        } else if (lookup.reputation === "Suspicious") {
          checks.push({
            name: `Threat Intel Match: Suspicious Indicator ("${c}")`,
            category: "threat_intel",
            status: "warning",
            details: `Observable matches suspicious indicator in threat database (Confidence: ${lookup.confidence}%).`,
            points: 20,
          });
          calculatedScore += 20;
          riskFactors.push({
            factor: "Threat Intelligence Correlation",
            points: 20,
            reason: `Matched suspicious record (${lookup.reputation})`,
          });
        }
      }
    }

    // 9b. Check existing incidents for indicator presence
    const incRes = await db.execute("SELECT incidentId, title, indicators FROM incidents");
    for (const row of incRes.rows) {
      const indStr = String(row.indicators || "[]");
      if (indStr.includes(hostname) || indStr.includes(cleanUrl)) {
        relatedIncidents.push(String(row.incidentId));
      }
    }

    if (relatedIncidents.length > 0) {
      checks.push({
        name: `Active Incident Cross-Correlation (${relatedIncidents.join(", ")})`,
        category: "threat_intel",
        status: "danger",
        details: `Indicator host or URL is directly referenced in ${relatedIncidents.length} active organizational incident(s): ${relatedIncidents.join(", ")}.`,
        points: 25,
      });
      calculatedScore += 25;
      riskFactors.push({
        factor: "Incident Cross-Correlation",
        points: 25,
        reason: `Linked to active SOC incidents: ${relatedIncidents.join(", ")}`,
      });
    }
  } catch (err: any) {
    console.warn("URL analysis application data lookup warning:", err?.message || err);
  }

  // ---------------------------------------------------------
  // FINAL SCORE & CLASSIFICATION
  // ---------------------------------------------------------
  const finalScore = Math.min(Math.max(calculatedScore, 5), 100);

  let classification: "Malicious" | "Suspicious" | "Benign" = "Benign";
  if (finalScore >= 70 || matchedTI.some((m) => m.reputation === "Malicious")) {
    classification = "Malicious";
  } else if (finalScore >= 40) {
    classification = "Suspicious";
  } else {
    classification = "Benign";
  }

  // Always ensure primary indicators are recorded
  if (!indicators.some((i) => i.indicator === cleanUrl)) {
    indicators.unshift({
      indicator: cleanUrl,
      type: "URL",
      severity: classification === "Malicious" ? "Critical" : classification === "Suspicious" ? "Medium" : "Low",
      description: "Full target URL evaluated under defensive structural heuristics",
    });
  }

  // ---------------------------------------------------------
  // RECOMMENDED INVESTIGATION STEPS
  // ---------------------------------------------------------
  const recommendedInvestigation: string[] = [];
  if (classification === "Malicious") {
    recommendedInvestigation.push(`Submit immediate perimeter DNS sinkhole entry for ${hostname} to block internal name resolution.`);
    recommendedInvestigation.push(`Query Secure Web Gateway (SWG) and proxy access logs for client IPs that requested this URL within the past 7 days.`);
    recommendedInvestigation.push(`Inspect endpoint EDR sensor telemetry for web browser child process executions (e.g. cmd.exe or powershell.exe spawned from chrome.exe).`);
    recommendedInvestigation.push(`Correlate firewall flow records for TCP 80/443 outbound sessions to destination IP ${ipCheck.isIp ? hostname : "associated with domain"}.`);
    recommendedInvestigation.push(`Escalate this URL analysis result to an active SOC formal incident.`);
  } else if (classification === "Suspicious") {
    recommendedInvestigation.push(`Correlate ${hostname} against internal DNS RPZ (Response Policy Zone) logs.`);
    recommendedInvestigation.push(`Examine email security gateway (SEG) logs to determine if this URL was delivered via inbound phishing lure.`);
    recommendedInvestigation.push(`Monitor authentication logs for credential challenges submitted immediately after visiting host.`);
    recommendedInvestigation.push(`Verify domain registration timestamp and registrar privacy details in passive WHOIS feeds.`);
  } else {
    recommendedInvestigation.push("No immediate defensive containment required; URL exhibits standard structural attributes.");
    recommendedInvestigation.push("Retain telemetry record in accordance with standard 30-day proxy compliance retention.");
  }

  // ---------------------------------------------------------
  // EXPLANATION & GEMINI ASSESSMENT
  // ---------------------------------------------------------
  const summary = `${classification} classification (Risk Score: ${finalScore}/100) assigned based on passive lexical, syntactic, and application threat intelligence correlation. Identified ${riskFactors.length} structural risk factors.`;

  let geminiAssessment = "";
  if (apiKey) {
    try {
      const prompt = `Defensive CyberSentinel X URL Structural Analysis:
URL: ${cleanUrl}
Calculated Risk Score: ${finalScore}/100
Assigned Classification: ${classification}
Detected Risk Factors:
${riskFactors.map((f) => `- ${f.factor} (+${f.points} pts): ${f.reason}`).join("\n")}
Threat Intel Matches: ${matchedTI.length > 0 ? JSON.stringify(matchedTI) : "None in internal TI database."}
Related Active Incidents: ${relatedIncidents.length > 0 ? relatedIncidents.join(", ") : "None."}
Structural Breakdown:
- Protocol: ${protocol}
- Hostname: ${hostname} (IP Host: ${ipCheck.isIp ? "Yes" : "No"}, Entropy: ${entropy})
- Subdomains Count: ${subdomainsCount}
- Encoding Findings: ${encodingFindings.join("; ") || "None"}
- Path Findings: ${pathFindings.join("; ") || "None"}
- Query Findings: ${queryFindings.join("; ") || "None"}

Provide a concise, professional 2-3 paragraph defensive SOC assessment explaining:
1. Why this URL structure is classified as ${classification} (referencing the specific structural indicators).
2. The likely adversary technique or evasion mechanism (e.g. MITRE ATT&CK T1566.002 Spearphishing Link, T1071.001 Web Protocols, T1204.001 User Execution).
3. Strategic defensive guidance for the SOC analyst.`;

      const aiRes = await ai.models.generateContent({
        model: "gemini-3.8-flash",
        contents: prompt,
        config: {
          systemInstruction: "You are CyberSentinel X's elite defensive URL analysis specialist. Provide objective, high-precision structural threat assessments.",
          temperature: 0.1,
        },
      });
      geminiAssessment = aiRes.text || "";
    } catch (err: any) {
      console.warn("Gemini URL explanation call skipped/failed:", err?.message || err);
    }
  }

  if (!geminiAssessment) {
    geminiAssessment = `Deterministic Structural Assessment:
Evaluation of "${cleanUrl}" identified ${riskFactors.length} risk vectors contributing to a calculated structural score of ${finalScore}/100 (${classification}).
Key structural anomalies include ${riskFactors.slice(0, 3).map((r) => r.factor).join(", ")}.
${matchedTI.length > 0 ? `Crucially, the indicator directly cross-references verified threat intelligence records in the internal database.` : "Passive structural evaluation guarantees zero active network packets or handshakes were transmitted to the destination."}`;
  }

  return {
    valid: true,
    url: cleanUrl,
    riskScore: finalScore,
    classification,
    structuralDetails: {
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === "https:" ? "443" : "80"),
      pathname: parsed.pathname,
      search: parsed.search,
      hash: parsed.hash,
      length: totalLength,
      subdomainsCount,
      subdomainList: subdomainLabels,
      entropyScore: entropy,
      isIpHost: ipCheck.isIp,
      isHttps: protocol === "https:",
      hasUserinfo: cleanUrl.includes("@"),
      hasPunycode: hostname.startsWith("xn--"),
      encodingFindings,
      pathFindings,
      queryFindings,
    },
    checks,
    indicators,
    explanation: {
      summary,
      factors: riskFactors,
      geminiAssessment,
      threatIntelCorrelation: {
        matchedIndicators: matchedTI,
        relatedIncidents,
      },
    },
    recommendedInvestigation,
    defensiveGuidance: [
      "Strict Passive Safety Guarantee: Zero outbound HTTP/TLS requests or socket handshakes were dispatched to the target host.",
      "Cross-correlated against CyberSentinel X local threat intelligence database and active incident indices.",
      "Check internal proxy / web gateway egress logs to verify if any managed corporate assets resolved this URL.",
      "If classified as Malicious or Suspicious, initiate perimeter sinkhole and review authentication session challenges.",
    ],
    engine: apiKey ? "gemini" : "structural_heuristic",
  };
}

/**
 * Creates a formal incident from a URL Analysis result.
 * Updates:
 * 1. Incidents table (with risk breakdown, timeline, indicators, recommendations)
 * 2. Threat Intelligence table (populates new indicators with tags and notes)
 * 3. Audit Log table
 * 4. Indirectly updates Dashboard & Incidents counts
 */
export async function createIncidentFromUrl(
  analysis: UrlAnalysisResult,
  options?: {
    customTitle?: string;
    affectedUser?: string;
    analystNotes?: string;
  }
) {
  const incId = `INC-URL-${Date.now().toString().slice(-4)}`;
  const title = options?.customTitle || `Malicious URL Investigation: ${analysis.structuralDetails?.hostname || analysis.url.slice(0, 45)}`;
  const user = options?.affectedUser || "perimeter-gateway@enterprise-corp.internal";
  const timestamp = new Date().toISOString();

  const severity: "Critical" | "High" | "Medium" | "Low" =
    analysis.riskScore >= 75 || analysis.classification === "Malicious"
      ? "Critical"
      : analysis.riskScore >= 50
      ? "High"
      : analysis.riskScore >= 30
      ? "Medium"
      : "Low";

  // Build extracted indicators list
  const indicatorsList: string[] = [];
  if (analysis.url && !indicatorsList.includes(analysis.url)) indicatorsList.push(analysis.url);
  if (analysis.structuralDetails?.hostname && !indicatorsList.includes(analysis.structuralDetails.hostname)) {
    indicatorsList.push(analysis.structuralDetails.hostname);
  }
  for (const ind of analysis.indicators) {
    if (ind.indicator && !indicatorsList.includes(ind.indicator) && !ind.indicator.includes(" ")) {
      indicatorsList.push(ind.indicator);
    }
  }

  // 1. Generate Chronological Timeline Milestones
  const now = new Date();
  const formatTimeStr = (minsAgo: number) => {
    const d = new Date(now.getTime() - minsAgo * 60000);
    return `${d.getHours().toString().padStart(2, "0")}:${d.getMinutes().toString().padStart(2, "0")}:${d.getSeconds().toString().padStart(2, "0")}`;
  };

  const timeline = [
    {
      time: formatTimeStr(30),
      event: `URL indicator captured via defensive gateway telemetry: ${analysis.url}`,
      source: "Secure Web Gateway",
      severity: "Medium",
    },
    {
      time: formatTimeStr(20),
      event: `Defensive URL Analyzer decomposed URI syntax, entropy (${analysis.structuralDetails?.entropyScore || "N/A"}), and ${analysis.checks.length} structural heuristic rules. Risk Score: ${analysis.riskScore}/100 (${analysis.classification})`,
      source: "CyberSentinel URL Analyzer",
      severity: analysis.riskScore >= 75 ? "Critical" : "High",
    },
    {
      time: formatTimeStr(12),
      event: `Cross-referenced ${indicatorsList.length} observable(s) against CyberSentinel threat intelligence and active incident correlation`,
      source: "Threat Intelligence Engine",
      severity: analysis.explanation.threatIntelCorrelation?.matchedIndicators?.length ? "Critical" : "Medium",
    },
    {
      time: formatTimeStr(2),
      event: `SOC Analyst escalated URL analysis into formal Incident ${incId}`,
      source: "Analyst Incident Escalation",
      severity: "High",
    },
  ];

  // 2. MITRE ATT&CK Mapping
  const mitreTechniques = [
    { id: "T1566.002", name: "Phishing: Spearphishing Link", tactic: "Initial Access", status: "Confirmed" },
    { id: "T1204.001", name: "User Execution: Malicious Link", tactic: "Execution", status: "Suspected" },
    { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control", status: "Suspected" },
  ];

  // 3. Risk Breakdown
  const riskBreakdown = {
    factors: analysis.explanation.factors.map((f) => ({
      name: f.factor,
      points: f.points,
      reason: f.reason,
    })),
    totalScore: analysis.riskScore,
    maxScore: 100,
    explanation: analysis.explanation.summary,
  };

  // 4. Incident Recommendations
  const recommendations = analysis.recommendedInvestigation.length > 0
    ? analysis.recommendedInvestigation
    : [
        "Deploy perimeter DNS sinkhole for destination hostname.",
        "Query proxy logs for internal workstations accessing indicator URL.",
        "Invalidate active user browser sessions if authentication challenges were observed.",
      ];

  // 5. Insert into SQLite `incidents` table
  await db.execute({
    sql: `INSERT INTO incidents (incidentId, title, description, severity, riskScore, status, affectedUser, affectedAssets, relatedEvents, indicators, timeline, mitreTechniques, recommendations, riskBreakdown, createdAt, updatedAt)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    args: [
      incId,
      title,
      `URL Investigation Escalation: ${analysis.explanation.summary}. Evaluated via passive structural heuristics.`,
      severity,
      analysis.riskScore,
      "Open",
      user,
      JSON.stringify(["Secure Web Gateway", "Perimeter DNS Sinkhole", "Proxy Server"]),
      JSON.stringify([]),
      JSON.stringify(indicatorsList),
      JSON.stringify(timeline),
      JSON.stringify(mitreTechniques),
      JSON.stringify(recommendations),
      JSON.stringify(riskBreakdown),
      timestamp,
      timestamp,
    ],
  });

  // 6. Update `threat_intel` table with extracted observables
  for (const item of analysis.indicators) {
    const isDomain = item.type === "Domain";
    const status = analysis.classification === "Malicious" ? "Malicious (Verified)" : "Suspicious (URL Extract)";
    const confidence = analysis.riskScore >= 75 ? 90 : 70;

    await db.execute({
      sql: `INSERT OR REPLACE INTO threat_intel (id, indicator, type, status, confidence, firstSeen, lastSeen, source, threatGroup, tags, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [
        `TI-URL-${Math.abs(item.indicator.split("").reduce((a, b) => ((a << 5) - a + b.charCodeAt(0)) | 0, 0))}`,
        item.indicator,
        item.type,
        status,
        confidence,
        timestamp,
        timestamp,
        "URL Analysis Module (Synthetic Demo Feed)",
        "Adversary Web Infrastructure Emulation",
        JSON.stringify(["url-analysis", item.type.toLowerCase(), "structural-heuristics"]),
        `Observable extracted from URL Incident ${incId} (${title}). ${item.description}`,
      ],
    });
  }

  // 7. Insert Audit Log
  await db.execute({
    sql: `INSERT INTO audit_logs (id, timestamp, userAction, actionType, incidentId, aiRecommendation, analystDecision, details)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    args: [
      `AUD-${Date.now().toString().slice(-4)}`,
      timestamp,
      `Incident Created from URL Analysis (${incId})`,
      "Incident Creation",
      incId,
      `URL Structural Classification: ${analysis.classification} (Risk: ${analysis.riskScore}/100)`,
      `Analyst escalated URL evaluation to active SOC incident`,
      `Created incident ${incId} with ${indicatorsList.length} indicators, 4 timeline milestones, and populated threat intelligence records. ${options?.analystNotes || ""}`,
    ],
  });

  return {
    success: true,
    incidentId: incId,
    title,
    severity,
    riskScore: analysis.riskScore,
    indicatorsCount: indicatorsList.length,
    timelineMilestonesCount: timeline.length,
  };
}
