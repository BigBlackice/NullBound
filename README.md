# NullBound

This is the interactive NiceGUI shell for the proposed recon workspace. The
Launchpad module cards open module-specific configuration panels, and the primary
rail destinations have project-aware views. ProjectDiscovery `httpx` can now be
launched with direct or saved project targets, with live output and durable runs.

The application entry point is `main.py`, UI composition and state live in
`dashboard_ui.py`, and visual styling lives in `styles.css`. Module definitions,
scan profiles, validation, and automatic ID allocation live in the
`recon_modules` package; the bundled catalog is `recon_modules/definitions.json`.
Project manifests, validation, filesystem persistence, and open-workspace state
live in the `nullbound_projects` package. UI-independent target normalization,
saved target sets, scope rules, enforcement evaluation, and launch-time context
live in `nullbound_scope`.
The adapter contract, subprocess lifecycle, cancellation, and portable run
manifests live in `nullbound_execution`. Module scan profiles store argument arrays;
NullBound never interpolates target input into a shell command.
The project-local SQLite schema, typed evidence records, parser contracts,
normalization, deduplication, scope review, and correlation rules live in
`nullbound_evidence`. Raw artifacts remain ordinary files; `project.db` is their
searchable, rebuildable index. Terminal project runs are indexed automatically:
Subfinder, dnsx, httpx, gau, and tlsx use native JSONL outputs, while Nmap uses
XML. Failed or cancelled scans can still
contribute complete records from partial artifacts, while parser failures are
recorded separately and never rewrite the scan's terminal status.

New projects default to the current user's NullBound data directory on every platform:

```text
~/.nullbound/projects/P-0001/
  project.json
  project.db
  scope.json  # created when target sets or scope rules are first saved
  runs/
    RUN-YYYYMMDD-HHMMSS-XXXXXX/
      run.json
      stdout.log
      stderr.log
      artifacts/
```

The parent directory can be changed while creating a project. Existing project
directories can be opened from anywhere on the local filesystem as long as they
contain a valid `project.json`; they do not need to remain below `.nullbound`.
Older projects without `scope.json` remain valid and load with empty scope data.
Their `project.db` index is created and migrated when the project is next opened.
Open project tabs are stored in local `~/.nullbound/workspace.json` state and are
restored after an application restart. Closing a tab removes it from that state;
the session file is local UI state and is not part of the portable project format.

Scope is opt-in at execution time. Direct targets work with or without a project,
and do not need to be added to project scope first. When enforcement is enabled,
an explicit denied rule blocks a target; an unmatched target is surfaced as
unknown rather than silently treated as denied. Review-required state and
ownership confidence are stored independently from allow/deny authorization.

Run the platform-neutral project-store tests with:

```bash
python -m unittest discover -v
```

## Run on Windows

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python .\main.py
```

Open <http://127.0.0.1:8080> in a browser.

### Install the Windows scanner tools locally

The PowerShell bootstrapper checks the executable paths configured in
`recon_modules/definitions.json`, the ignored `.nullbound-tools` directory, and
the current `PATH`. Missing Subfinder, dnsx, httpx, gau, and tlsx binaries are fetched
from their official GitHub releases. Nmap uses its official signed Windows
installer because current portable ZIP builds are restricted to Nmap OEM users.

```powershell
# Report only; do not download or change PATH
.\scripts\setup-tools.ps1 -CheckOnly

# Install missing tools locally and add the local directories to the user PATH
.\scripts\setup-tools.ps1
```

Nmap installation displays a UAC prompt. If Npcap is absent, its installer opens
interactively because the free Npcap edition cannot legally/technically be
installed silently; keep Npcap selected. If Npcap is already installed, the Nmap
step can run silently. Use `-SkipNmap` to install only the portable tools, or
`-NoPersistPath` to avoid changing the user `PATH`. The tool directory, download
cache, and extracted licenses are excluded from Git. Gau has no additional runtime
dependency. OpenSSL is optional for tlsx and is only needed for its OpenSSL scan
mode or the extra fallback coverage from that mode.

`scripts/amass-mullvad-dns.ps1` remains available as a manual Windows testing
helper for temporarily allowing a broad public resolver pool through Mullvad. It
is not called by NullBound or by the tool bootstrapper.

NullBound binds to localhost by default. To make it reachable on a trusted LAN,
opt in explicitly:

```powershell
python .\main.py --host 0.0.0.0 --port 8080
```

Non-loopback binding prints a startup warning because remote clients can use the
host filesystem directory browser. Authentication has not been implemented yet.

## Run on Linux or macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python main.py
```

### Install the Linux scanner tools

The Bash bootstrapper checks the module catalog, the ignored `.nullbound-tools`
directory, and the current `PATH`. On Debian-family, RHEL-family, and Arch-family
systems it uses `apt`, `dnf`/`yum`, or `pacman` first. Remaining portable Go tools
are installed into the project-local directory, with official GitHub release
archives as a fallback.

```bash
# Report only
bash ./scripts/setup-tools.sh --check-only

# Install missing tools and add the local bin directory to PATH
bash ./scripts/setup-tools.sh
```

Nmap and common build/runtime prerequisites use the detected system package
manager. Flatpak is intentionally not used for these command-line scanners because
there are no suitable official Flatpak packages and sandboxed executables would not
behave like normal `PATH` commands. The installer falls back to upstream Go builds,
release archives, and an Nmap source build when required.

The same `--host` and `--port` options are available on Linux and macOS.

The working roadmap is in [`todo.md`](todo.md). Original brainstorming notes and
the Tkinter experiment are preserved in [`archived/`](archived/).
