"""Temporary project records used by the interactive UI prototype."""

ASSETS = (
    {"id": "AS-0024", "type": "DOMAIN", "name": "portal.acme.test", "address": "203.0.113.42", "ports": "80, 443", "scope": "ALLOWED", "source": "AMASS", "first_seen": "2026-09-06 11:44", "last_seen": "2026-09-07 12:42", "technology": "nginx / Python", "provenance": "RUN-008 / amass -> dnsx -> httpx", "notes": "Primary customer portal and API entry point."},
    {"id": "AS-0023", "type": "HOST", "name": "admin.acme.test", "address": "198.51.100.14", "ports": "443, 8443", "scope": "REVIEW", "source": "HTTPX", "first_seen": "2026-09-06 12:10", "last_seen": "2026-09-07 12:37", "technology": "Jetty / Admin Console", "provenance": "RUN-007 / httpx", "notes": "Publicly reachable management interface."},
    {"id": "AS-0019", "type": "IPV4", "name": "edge-01", "address": "203.0.113.42", "ports": "80, 443", "scope": "ALLOWED", "source": "DNSX", "first_seen": "2026-09-06 11:48", "last_seen": "2026-09-07 12:35", "technology": "Reverse proxy", "provenance": "RUN-006 / dnsx", "notes": "Shared edge address for public web properties."},
    {"id": "AS-0014", "type": "URL", "name": "https://api.acme.test/v2", "address": "203.0.113.42", "ports": "443", "scope": "ALLOWED", "source": "GAU", "first_seen": "2026-09-06 13:21", "last_seen": "2026-09-07 11:58", "technology": "JSON API", "provenance": "RUN-005 / gau", "notes": "Versioned API base discovered in archived URLs."},
    {"id": "AS-0009", "type": "DOMAIN", "name": "legacy.acme.test", "address": "192.0.2.28", "ports": "443", "scope": "ALLOWED", "source": "TLSX", "first_seen": "2026-09-06 14:06", "last_seen": "2026-09-07 12:19", "technology": "Apache / Legacy TLS", "provenance": "RUN-004 / tlsx", "notes": "Certificate identity differs from the active hostname."},
    {"id": "AS-0004", "type": "DOMAIN", "name": "status.acme.test", "address": "203.0.113.77", "ports": "443", "scope": "REVIEW", "source": "AMASS", "first_seen": "2026-09-06 09:02", "last_seen": "2026-09-07 11:44", "technology": "Static status page", "provenance": "RUN-002 / amass", "notes": "Ownership has not yet been confirmed."},
)

EVIDENCE = (
    {
        "id": "EN-0046", "kind": "ASSET", "identifier": "10.10.10.1",
        "scope": "IN SCOPE", "scope_anchor": "10.10.10.0/24", "relations": "06",
        "artifact_count": "05", "updated": "12:42:18",
        "context": "Infrastructure node discovered inside the authorized network range.",
        "identifiers": (("IPV4", "10.10.10.1"), ("HOST", "server01"),
                        ("FQDN", "server01.example.com"), ("DOMAIN", "example.com")),
        "artifacts": (
            ("DNS", "EV-0046", "Forward and reverse records", "DNSX", "VERIFIED"),
            ("PORTS", "EV-0045", "TCP service inventory", "NMAP", "VERIFIED"),
            ("HTTP", "EV-0044", "Web service response", "HTTPX", "VERIFIED"),
            ("CERT", "EV-0043", "Presented TLS certificate", "TLSX", "VERIFIED"),
            ("FINDING", "FW-1042", "Template injection result", "NUCLEI", "VERIFIED"),
        ),
    },
    {
        "id": "EN-0041", "kind": "DOMAIN", "identifier": "example.com",
        "scope": "IN SCOPE", "scope_anchor": "example.com", "relations": "18",
        "artifact_count": "04", "updated": "12:37:09",
        "context": "Root engagement domain and parent for discovered hostnames.",
        "identifiers": (("DOMAIN", "example.com"), ("NAMESERVER", "ns1.example.com"),
                        ("ORG", "Example Corporation")),
        "artifacts": (
            ("DNS", "EV-0041", "Authoritative record set", "DNSX", "VERIFIED"),
            ("OSINT", "EV-0040", "Registration record", "WHOIS", "VERIFIED"),
            ("OUTPUT", "EV-0039", "Passive subdomain results", "AMASS", "VERIFIED"),
            ("MANIFEST", "EV-0038", "Discovery run manifest", "BLACKWALL", "VERIFIED"),
        ),
    },
    {
        "id": "EN-0036", "kind": "VULNERABILITY", "identifier": "CVE-2025-29927",
        "scope": "IN SCOPE", "scope_anchor": "10.10.10.1", "relations": "04",
        "artifact_count": "03", "updated": "12:19:51",
        "context": "Scanner result attached to an in-scope service and its supporting evidence.",
        "identifiers": (("CVE", "CVE-2025-29927"), ("CWE", "CWE-288"),
                        ("ASSET", "10.10.10.1"), ("SERVICE", "server01.example.com:443")),
        "artifacts": (
            ("FINDING", "FW-1029", "Authorization bypass result", "NUCLEI", "VERIFIED"),
            ("HTTP", "EV-0036", "Proof request and response", "NUCLEI", "VERIFIED"),
            ("OUTPUT", "EV-0035", "Scanner JSONL record", "NUCLEI", "VERIFIED"),
        ),
    },
    {
        "id": "EN-0019", "kind": "IDENTITY", "identifier": "alice@example.com",
        "scope": "IN SCOPE", "scope_anchor": "alice@example.com", "relations": "05",
        "artifact_count": "03", "updated": "10:55:02",
        "context": "Employee identity retained through an explicitly scoped email identifier.",
        "identifiers": (("EMAIL", "alice@example.com"), ("USERNAME", "a.smith"),
                        ("DISPLAY NAME", "Alice Smith"), ("DOMAIN", "example.com")),
        "artifacts": (
            ("OSINT", "EV-0019", "Public staff directory record", "MANUAL", "VERIFIED"),
            ("DOCUMENT", "EV-0018", "Conference speaker biography", "MANUAL", "VERIFIED"),
            ("IMAGE", "EV-0017", "Profile image capture", "MANUAL", "VERIFIED"),
        ),
    },
    {
        "id": "EN-0005", "kind": "URL", "identifier": "https://server01.example.com/admin",
        "scope": "IN SCOPE", "scope_anchor": "*.example.com", "relations": "04",
        "artifact_count": "04", "updated": "09:08:47",
        "context": "Administrative route connected to the in-scope server and domain.",
        "identifiers": (("URL", "https://server01.example.com/admin"),
                        ("FQDN", "server01.example.com"), ("IPV4", "10.10.10.1")),
        "artifacts": (
            ("HTTP", "EV-0005", "Administrative login response", "HTTPX", "VERIFIED"),
            ("IMAGE", "EV-0004", "Login page screenshot", "MANUAL", "VERIFIED"),
            ("HEADER", "EV-0003", "Server fingerprint headers", "HTTPX", "VERIFIED"),
            ("MANIFEST", "EV-0002", "Probe run manifest", "BLACKWALL", "VERIFIED"),
        ),
    },
)

SCOPE_RULES = (
    {"id": "SC-0027", "target": "*.acme.test", "type": "DOMAIN", "decision": "ALLOWED", "ownership": "CONFIRMED", "source": "ENGAGEMENT", "updated": "09-06 08:30", "reason": "Primary assessment domain supplied by the client.", "applies": "All matching subdomains; exclusions below take precedence.", "notes": "Standard web testing permitted during the engagement window."},
    {"id": "SC-0022", "target": "admin.acme.test", "type": "DOMAIN", "decision": "REVIEW REQUIRED", "ownership": "LIKELY", "source": "DISCOVERY", "updated": "09-07 12:38", "reason": "Discovered management interface not listed explicitly in the authorization letter.", "applies": "Exact hostname only.", "notes": "Passive collection allowed; active testing waits for operator review."},
    {"id": "SC-0018", "target": "203.0.113.0/28", "type": "CIDR", "decision": "ALLOWED", "ownership": "CONFIRMED", "source": "ENGAGEMENT", "updated": "09-06 08:31", "reason": "Client-owned public edge range.", "applies": "All addresses in the CIDR except explicit exclusions.", "notes": "Rate limit: 50 requests per second across the range."},
    {"id": "SC-0013", "target": "203.0.113.8", "type": "IPV4", "decision": "DENIED", "ownership": "CONFIRMED", "source": "EXCLUSION", "updated": "09-06 08:34", "reason": "Production payment service excluded from active testing.", "applies": "Exact address and every service hosted on it.", "notes": "May appear in evidence but must never be sent to a module when scope enforcement is active."},
    {"id": "SC-0008", "target": "status.acme.test", "type": "DOMAIN", "decision": "REVIEW REQUIRED", "ownership": "UNKNOWN", "source": "DISCOVERY", "updated": "09-07 11:46", "reason": "Passive DNS suggests a relationship but ownership is not established.", "applies": "Exact hostname only.", "notes": "Retain discovery; hide from normal active target selection."},
    {"id": "SC-0003", "target": "https://portal.acme.test/logout", "type": "URL", "decision": "DENIED", "ownership": "CONFIRMED", "source": "EXCLUSION", "updated": "09-06 08:40", "reason": "State-changing endpoint excluded to protect active user sessions.", "applies": "Exact normalized URL and equivalent query variants.", "notes": "Non-invasive retrieval of surrounding application pages remains allowed."},
)

RUNS = (
    {"id": "RUN-008", "module": "NUCLEI", "target": "portal.acme.test", "project": "P-0142", "state": "RUNNING", "duration": "00:02:41", "started": "12:40:02", "exit_code": "—", "artifacts": "4", "profile": "Web vulnerabilities", "command": "nuclei -u https://portal.acme.test -jsonl", "context": "Project assets / scope enforced", "summary": "Scanning 42 templates; 31 completed."},
    {"id": "RUN-007", "module": "HTTPX", "target": "24 project assets", "project": "P-0142", "state": "COMPLETED", "duration": "00:01:18", "started": "12:35:51", "exit_code": "0", "artifacts": "3", "profile": "Standard web metadata", "command": "httpx -l targets.txt -title -tech-detect -json", "context": "Project assets / scope enforced", "summary": "22 hosts responded; 2 hosts timed out."},
    {"id": "RUN-006", "module": "TLSX", "target": "legacy.acme.test:443", "project": "P-0142", "state": "COMPLETED", "duration": "00:00:22", "started": "12:19:29", "exit_code": "0", "artifacts": "2", "profile": "Certificate summary", "command": "tlsx -host legacy.acme.test:443 -json", "context": "Direct target / project attached", "summary": "Certificate and supported protocol metadata captured."},
    {"id": "RUN-005", "module": "DNSX", "target": "18 project assets", "project": "P-0142", "state": "COMPLETED", "duration": "00:00:31", "started": "11:48:02", "exit_code": "0", "artifacts": "3", "profile": "Standard resolution", "command": "dnsx -l domains.txt -a -aaaa -cname -json", "context": "Project assets / scope enforced", "summary": "18 names resolved to 11 unique addresses."},
    {"id": "RUN-004", "module": "NMAP", "target": "198.51.100.14", "project": "P-0142", "state": "FAILED", "duration": "00:00:08", "started": "11:21:44", "exit_code": "2", "artifacts": "2", "profile": "Top 1000 TCP", "command": "nmap -sT --top-ports 1000 198.51.100.14", "context": "Direct target / project attached", "summary": "Process exited before producing normalized results."},
    {"id": "RUN-003", "module": "HTTPX", "target": "admin.acme.test:8443", "project": "P-0142", "state": "CANCELLED", "duration": "00:00:47", "started": "10:54:15", "exit_code": "—", "artifacts": "2", "profile": "Extended fingerprint", "command": "httpx -u https://admin.acme.test:8443 -title -tech-detect", "context": "Direct target / scope override", "summary": "Cancelled by operator after the service was identified."},
    {"id": "RUN-002", "module": "AMASS", "target": "acme.test", "project": "P-0142", "state": "COMPLETED", "duration": "00:06:14", "started": "09:02:33", "exit_code": "0", "artifacts": "3", "profile": "Passive discovery", "command": "amass enum -d acme.test -passive", "context": "Direct target / project attached", "summary": "18 unique hostnames collected from passive sources."},
    {"id": "RUN-001", "module": "NMAP", "target": "192.0.2.28", "project": "—", "state": "QUEUED", "duration": "—", "started": "—", "exit_code": "—", "artifacts": "0", "profile": "Web ports", "command": "nmap -sT -p 80,443,8080,8443 192.0.2.28", "context": "No project / direct target", "summary": "Waiting for an available execution slot."},
)
