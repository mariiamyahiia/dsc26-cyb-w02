# tmcheck: threat model as code (DSC 2026 Cyber W2)

## Commands
- Setup: `uv venv --python 3.12 && source .venv/bin/activate && uv pip install -r requirements.txt`
- Tests: `python -m pytest -q` from the repo root. Never plain `pytest` (it may not find `tmcheck`).
- Check the model: `python -m tmcheck models/rawaj_scoring.yaml` (exit 0 clean, 1 findings, 2 cannot load)

## Conventions that differ from defaults
- Load YAML with `yaml.safe_load` only. Never `yaml.load`, `FullLoader` or `UnsafeLoader`.
- A score is valid only if `type(v) is int` and 1 to 5. `True` and `4.0` are not scores.
- STRIDE order is S, T, R, I, D, E, not alphabetical. Gaps sort by ref, then STRIDE order.
- Zones, elements, flows and threats share one id space. A repeated id is DUPLICATE_ID.
- Standard library and the pinned PyYAML only. Do not add packages.
- Keep function names and signatures in `tmcheck/core.py`; the tests import them.
- Code lives in `tmcheck/` only. No root `conftest.py`, no top-level file named like a stdlib module (`yaml.py`).

## Where things are (read when relevant)
- Rules and the STRIDE-per-element table: README.md, section "What to build"
- Threat model: models/rawaj_scoring.yaml
- Public tests: tests/test_public.py

## Editing models/rawaj_scoring.yaml
- Never delete a starter item or change a starter zone's trust, element's kind/zone/holds_pii/is_log, flow's source/target, or threat's target/category. A flow's protocol may change.
- Titles: unique ignoring case and surrounding spaces, 15+ characters, double-quoted.
- New ids must not collide with any zone, element, flow or threat id.

## Known traps
- Flows between zones with equal trust still cross (rails and dmz). Crossing means a different zone, not a different trust.
- A data store with `holds_pii: true` needs an I threat even when it is not on a crossing flow.
- A store gets R only if `is_log: true`; flows take T, I, D only.

## Security
- Never read, print or commit `.env`, keys, tokens or real logs. Models and fixtures use synthetic data only.

## Before saying a task is done
- `python -m pytest -q` passes and new behaviour has a new test.
- `python -m tmcheck models/rawaj_scoring.yaml` exits 0 with empty issues, gaps and policy.
- `AI_USAGE.md` keeps `## Tools`, `## What AI got wrong`, `## In my own words`; the last is written by the student, not the agent.