# DEEPSIGHT handoff — version 1.1.0

Product: **DEEPSIGHT** · Slogan: **See beyond the surface.**
MACHINE LEARNING-DRIVEN ATTACK SURFACE INTELLIGENCE AND VULNERABILITY MANAGEMENT PLATFORM

`ASIVM` (Attack Surface Intelligence and Vulnerability Management) is only a technical compatibility prefix
(`ASIVM_*` environment variables, `asivm` database and logger names).

## Read in this order
1. `README.md` — run, demo walkthrough, checks, operations, configuration.
2. `docs/IMPLEMENTATION_STATUS.md` — what is implemented and measured (Status) vs. what is planned (Roadmap).
3. `docs/QA.md` — exact commands, results and unresolved limits for this release.
4. `CHANGELOG.md` — what changed from 1.0.2.

## State of the work
- All seven phases of the 1.1.0 brief are implemented except one optional item: no model trained on CISA KEV membership was built.
- Verified for this release: full test suite on SQLite and on PostgreSQL 16, lint, `node --check`, compileall, backup/restore, load
  tests, fixed evaluation and a browser walk through every page. See `docs/QA.md`.
- **Open items**
  - `pip-audit` reports PyJWT 2.12.1 advisories. pip-audit lists fixes in PyJWT 2.13.0–2.15.0 (one advisory lists no fixed version). Tokens and sessions are out of
    scope for this work, so the upgrade was left for a deliberate, separately tested change. CI will fail on the `pip-audit` step until then.
  - The Docker image build was not repeated in the final pass (no Docker daemon in the recovery environment). The saved build log
    was produced from a `Dockerfile.qa` that is not part of this repository.
  - `scripts/check_scope.py` needs the original 1.0.2 archive, which is not in this repository.
  - Evaluation fixtures and load tests are small and synthetic; see the limits in `docs/QA.md`.

## Scope rule
Login, sign-in, sessions, tokens, passwords, roles and access control are deliberately untouched.

The supplied archive contained no database; no user data or credentials are included in this package.
