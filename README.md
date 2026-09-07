# Recon Dashboard

This is the interactive NiceGUI shell for the proposed recon workspace. The
Launchpad module cards open module-specific configuration panels, while the
remaining navigation destinations intentionally show a shared not-yet-implemented
view. Tool execution, project data, and persistence are not connected yet.

The application entry point is `main.py`, UI composition and state live in
`dashboard_ui.py`, and visual styling lives in `styles.css`. Module definitions,
scan profiles, validation, and automatic ID allocation live in the
`recon_modules` package; the bundled catalog is `recon_modules/definitions.json`.

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
