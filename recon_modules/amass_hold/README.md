# Amass integration hold

Amass support was removed from NullBound's active catalog, adapter registry,
evidence parser registry, and tool bootstrap on 2026-09-27. The v5 engine and OAM
database architecture duplicated NullBound's own storage/correlation layer and
produced excessive per-run artifacts for the default discovery workflow.

This directory is an inert source backup only. Files use `.disabled` suffixes,
the directory has no `__init__.py`, and no active NullBound module imports or
registers anything here. Subfinder now provides passive subdomain discovery.

Preserved work:

- managed hidden Amass engine companion and isolated run-local configuration;
- live OAM database progress counts;
- lossless read-only OAM SQLite entity, edge, tag, confidence, and provenance parser;
- former run-artifact selection logic and Windows release bootstrap entries;
- the former module catalog profiles;
- the Windows Mullvad resolver workaround used during development.

If Amass is reconsidered, review upstream storage behavior and adapter boundaries
before reconnecting any of this code.
