# Recon Dashboard

This is the interactive NiceGUI shell for the proposed recon workspace. The
Launchpad module cards open module-specific configuration panels, and the primary
rail destinations have project-aware views. ProjectDiscovery `httpx` can now be
launched with direct or saved project targets, with live output and durable runs.

The application entry point is `main.py`, UI composition and state live in
`dashboard_ui.py`, and visual styling lives in `styles.css`. Module definitions,
scan profiles, validation, and automatic ID allocation live in the
`recon_modules` package; the bundled catalog is `recon_modules/definitions.json`.
Project manifests, validation, filesystem persistence, and open-workspace state
live in the `blackwall_projects` package. UI-independent target normalization,
saved target sets, scope rules, enforcement evaluation, and launch-time context
live in `blackwall_scope`.
The adapter contract, subprocess lifecycle, cancellation, and portable run
manifests live in `blackwall_execution`. Module scan profiles store argument arrays;
Blackwall never interpolates target input into a shell command.
The project-local SQLite schema, typed evidence records, parser contracts,
normalization, deduplication, scope review, and correlation rules live in
`blackwall_evidence`. Raw artifacts remain ordinary files; `project.db` is their
searchable, rebuildable index. Terminal project runs are indexed automatically:
Amass uses its native OAM SQLite `asset.db`, Nmap uses XML, and dnsx, httpx, gau,
and tlsx use their native JSONL outputs. Failed or cancelled scans can still
contribute complete records from partial artifacts, while parser failures are
recorded separately and never rewrite the scan's terminal status.

New projects default to the current user's Blackwall directory on every platform:

```text
~/.blackwall/projects/P-0001/
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
contain a valid `project.json`; they do not need to remain below `.blackwall`.
Older projects without `scope.json` remain valid and load with empty scope data.
Their `project.db` index is created and migrated when the project is next opened.

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

Blackwall binds to localhost by default. To make it reachable on a trusted LAN,
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

The same `--host` and `--port` options are available on Linux and macOS.

The working roadmap is in [`todo.md`](todo.md). Original brainstorming notes and
the Tkinter experiment are preserved in [`archived/`](archived/).
