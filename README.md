# Recon Dashboard

This is the interactive NiceGUI shell for the proposed recon workspace. The
Launchpad module cards open module-specific configuration panels, and the primary
rail destinations have project-aware prototype views. Tool execution and record
persistence are not connected yet.

The application entry point is `main.py`, UI composition and state live in
`dashboard_ui.py`, and visual styling lives in `styles.css`. Module definitions,
scan profiles, validation, and automatic ID allocation live in the
`recon_modules` package; the bundled catalog is `recon_modules/definitions.json`.
Project manifests, validation, filesystem persistence, and open-workspace state
live in the `blackwall_projects` package.

New projects default to the current user's Blackwall directory on every platform:

```text
~/.blackwall/projects/P-0001/
  project.json
  runs/
```

The parent directory can be changed while creating a project. Existing project
directories can be opened from anywhere on the local filesystem as long as they
contain a valid `project.json`; they do not need to remain below `.blackwall`.

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

## Run on Linux or macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python main.py
```

The working roadmap is in [`todo.md`](todo.md). Original brainstorming notes and
the Tkinter experiment are preserved in [`archived/`](archived/).
