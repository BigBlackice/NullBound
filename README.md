# NULL//BOUND

NullBound is a local-first reconnaissance workspace for launching security tools,
watching them run, and turning their output into organized assets and evidence.
It keeps commands, logs, artifacts, scope, and discovered data together without
requiring a paid proxy or hosted service.


## What NullBound can do

- Run a tool immediately against a direct target; creating a project is optional.
- Watch live output, cancel active scans, and inspect the exact command before it
  runs.
- Keep persistent run history, logs, and downloadable raw artifacts in a project.
- Browse normalized assets and evidence without replacing the original tool output.
- Add domains, IP addresses, CIDRs, URLs, wildcards, or regular expressions to
  project scope.
- Filter Runs, Assets, and Findings by in-scope or out-of-scope state.
- Mark findings as candidate, validated, false positive, or accepted risk without
  changing their preserved evidence.
- Create and edit tool launchers and scan profiles from the application.
- Run the project-only Web Discovery module to pass reviewed scope seeds through
  Subfinder, dnsx, and httpx while retaining each tool as a separate auditable run.
- Run Web Enumeration against every compatible asset beneath one selected scope
  item, using either a quick httpx/tlsx chain or GAU followed by deeper HTTP/TLS
  collection. A third chain probes HTTP services and runs bounded recursive FFUF
  directory discovery from an operator-selected wordlist.
- Reopen project tabs automatically after restarting NullBound. Projects you close
  stay closed.
- Choose Standard, Broad, or Recursive passive profiles for Web Discovery.
- Launch safe Nuclei checks, low-impact sqlmap detection, or a capped CSRF-aware
  Brutepyweb password test as separate operator-controlled attack runs.
- Enforce an application proxy for compatible tools; incompatible launchers are
  blocked instead of silently bypassing it.

Scope is advisory by default. An explicit deny rule only blocks a matching launch
when you enable scope enforcement.

## Included tool launchers

| Tool | Purpose |
| --- | --- |
| Subfinder | Passive subdomain discovery |
| dnsx | DNS resolution and record collection |
| Nmap | Port and service discovery |
| httpx | HTTP probing and web metadata |
| gau | Known URL collection from public archives |
| ffuf | Directory and file discovery |
| tlsx | TLS and certificate inspection |
| Nuclei | Safe-template vulnerability matching |
| sqlmap | Low-impact SQL injection detection |
| Brutepyweb | Capped CSRF-aware password response testing |

Brutepyweb is bundled with NullBound. The other tools are separate programs that
NullBound can detect or install with the included setup scripts.

## Quick start on Linux

Python 3.11 or 3.12 is recommended.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# Check which scanner tools are already available
bash ./scripts/setup-tools.sh --check-only

# Install missing scanner tools
bash ./scripts/setup-tools.sh
source ~/.profile

python main.py
```

The tool installer supports Debian/Ubuntu, RHEL-family distributions, and Arch
Linux. It prefers the system package manager for Nmap and common prerequisites,
then uses upstream Go packages or official release archives for the remaining
tools. Portable tools are kept in the ignored `.nullbound-tools` directory.

Useful installer options:

```bash
bash ./scripts/setup-tools.sh --skip-nmap
bash ./scripts/setup-tools.sh --no-persist-path
bash ./scripts/setup-tools.sh --force
```

## Quick start on Windows

Use Python 3.11 or 3.12.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# Check which scanner tools are already available
.\scripts\setup-tools.ps1 -CheckOnly

# Install missing scanner tools and add them to your user PATH
.\scripts\setup-tools.ps1

python .\main.py
```

The Windows installer keeps portable tools under `.nullbound-tools`. Nmap uses
its official Windows installer and may display a UAC prompt. If Npcap is missing,
its free installer must be completed interactively; keep Npcap selected.

Useful installer options:

```powershell
.\scripts\setup-tools.ps1 -SkipNmap
.\scripts\setup-tools.ps1 -NoPersistPath
.\scripts\setup-tools.ps1 -Force
```

Open <http://127.0.0.1:8080> after starting NullBound.

## Your first scan

1. Open **Launchpad** and choose a tool.
2. Enter a target or select targets saved in the active project.
3. Choose a scan profile and review the command preview.
4. Enable scope enforcement if explicit deny rules should block matching targets.
   Targets not matched by a rule remain classified as unknown rather than blocked.
5. Launch the run and follow its progress in **Run Output**.
6. Open **Runs** to revisit its logs and artifacts. Project runs are also indexed
   into **Assets**, **Evidence**, and **Findings** where applicable.

Runs started without a project are temporary and exist only for the current
NullBound session. When you create a project, NullBound can attach completed
session runs to it or permanently delete them. Active session runs must finish or
be cancelled first.

For multi-step discovery, open a project, add an allowed domain or HTTP/S URL on
the **Scope** page, then select **Web Discovery** below the divider on Launchpad.
Review the scope seeds and three command previews before launching it.

Web Enumeration selects one specific scope rule. An exact domain such as
`example.com` does not include its subdomains; use `*.example.com` when discovered
subdomains should be enumerated. The recursive directory chain also requires a
local FFUF wordlist and an explicit depth from 1 to 10. On Kali, NullBound reads
`/usr/share/seclists/Discovery/Web-Content`, defaults to
`raft-medium-directories.txt`, and exposes the other text lists in the FFUF
wordlist dropdown. Every project has separate `wordlists/web-content/` and
`wordlists/passwords/` folders. Their project-relative locations can be changed
under **Settings > General**. Kali SecLists remains available when installed;
project files provide the fallback, and a custom absolute path can still be entered.

After discovery has populated **Assets**, select **Web Enumeration** on Launchpad.
Choose one scope item and a tool chain. NullBound expands that scope root through
recorded Evidence relationships, previews a bounded target sample, and snapshots
the complete target set into each ordinary tool run when launched.

## Projects and saved data

Projects keep an engagement's scope, run history, raw artifacts, and normalized
records together. By default they are created under:

```text
~/.nullbound/projects/P-0001/
  project.json
  project.db
  scope.json
  wordlists/
    web-content/
    passwords/
  runs/
    RUN-YYYYMMDD-HHMMSS-XXXXXX/
      run.json
      console.log
      stdout.log
      stderr.log
      artifacts/
```

You can choose another parent directory when creating a project or open an
existing project from elsewhere on disk. Raw scanner output remains in ordinary
files; `project.db` contains the searchable asset and evidence index.

Open project tabs are remembered in `~/.nullbound/workspace.json`. Closing a
project tab removes it from the next-start list without deleting the project.

### Retention, backup, and cleanup

NullBound does not automatically expire project runs, artifacts, findings, or
assets. Back up a project by closing NullBound and copying its entire project
directory. Copying the whole directory keeps the manifest, scope, wordlists, run
artifacts, and SQLite database together; copying only `project.db` may miss an
active SQLite WAL file.

Project deletion is deliberately left to the operator's normal filesystem tools.
Closing a project tab never deletes it. Runs made without a project are the one
exception: they use a process-temporary directory and disappear when NullBound
exits unless they are attached while creating a project.

Open a project in only one NullBound process at a time. SQLite serializes database
writes, but this release does not lock the project manifest, scope document, and
run directories across multiple application processes.

## Scope behavior

The Scope page shows only rules you explicitly add. Supported entries include:

- Domains and wildcard domains such as `*.example.com`
- IPv4 and IPv6 addresses
- CIDR networks
- Exact URLs and wildcard URL paths
- Regular expressions when regex matching is explicitly selected

Regex rules are marked separately from standard scope entries. Assets discovered
by scans are evaluated against the active project's rules and can also be added to
scope from the Assets page.

Scope enforcement is opt-in for each launch. With enforcement disabled, scope is
used for classification and filtering rather than silently preventing work.

## Tool-specific notes

- OpenSSL is optional for tlsx. The bundled profiles use tlsx's built-in TLS
  engines; OpenSSL is only needed for explicit OpenSSL mode and its additional
  fallback coverage.
- `scripts/amass-mullvad-dns.ps1` is a manual Windows testing helper for temporarily
  allowing a broad public DNS resolver pool through Mullvad. NullBound and the tool
  installer never run it automatically.
- The Bash tool bootstrapper currently supports Linux only. The NullBound
  application can run on macOS, but scanner tools must be installed manually and
  made available on `PATH`.
- Nuclei is restricted to HTTP templates and excludes templates tagged intrusive,
  denial-of-service, fuzzing, or brute force in the included profiles.
  sqlmap runs at level/risk 1 without extraction or takeover flags. Brutepyweb is
  capped by default, preserves matched passwords in local logs and artifacts, and
  compares status, size, redirect, URL, and configured success signals against
  known-invalid controls. Repeatable differentials are recorded as validated;
  unconfirmed differences remain candidates. Finding details mask passwords by
  default and provide reveal and copy controls. Project databases, run logs, and
  artifacts still contain the plaintext values and must be handled as sensitive data.

Scanner executables are downloaded only when the operator runs a setup script and
are not part of the NullBound source distribution. See
[`THIRD_PARTY.md`](THIRD_PARTY.md) before redistributing a prepared tool directory.

## Proxy routing

Configure the application proxy under **Settings > Proxy**, then use the top-bar
Proxy checkbox to enforce or disable it. NullBound passes the proxy explicitly to
tools that support the selected HTTP or SOCKS5 protocol and clears inherited proxy
environment variables when the checkbox is off. A run is blocked when its adapter
cannot honor the selected proxy, which is common for DNS and raw-socket tools.

Proxy authentication is intentionally not stored in this release, because proxy
credentials would otherwise leak into command previews and run manifests. A custom
CA certificate can be selected for HTTPS interception.

## Network access

NullBound listens only on localhost by default. You can expose it to a trusted LAN
explicitly:

```bash
python main.py --host 0.0.0.0 --port 8080
```

There is currently no authentication. Remote users can access functionality that
includes choosing project directories on the host, so do not expose NullBound to
an untrusted network or the public internet.

## Tests and roadmap

Run the test suite with:

```bash
python -m unittest discover -s tests -v
```
Planned features and longer-term performance work are tracked in
[`todo.md`](todo.md).
