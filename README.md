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
- Create and edit tool launchers and scan profiles from the application.
- Reopen project tabs automatically after restarting NullBound. Projects you close
  stay closed.

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
| tlsx | TLS and certificate inspection |

These tools are separate programs. NullBound can detect existing installations or
install them with the included setup scripts.

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

## Projects and saved data

Projects keep an engagement's scope, run history, raw artifacts, and normalized
records together. By default they are created under:

```text
~/.nullbound/projects/P-0001/
  project.json
  project.db
  scope.json
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
Scope and Proxy enforcement not yet implemented.

Planned features and longer-term performance work are tracked in
[`todo.md`](todo.md).
