# Benchmark results

Scenario: `scenarios/billing-api.md` · Scorer: `score.py` (22 checks, weights 1-3).

## Calibration (the scorer itself)

| Date | Implementation | Valid | Score | By category | Static scan (critical/high/medium/low) |
|---|---|---|---|---|---|
| 2026-11-03 | `apps/reference_app.py` | yes | 100% | authn 100, authz 100, injection 100, data 100, ops 100 | 0 / 0 / 0 / 0 |
| 2026-11-03 | `apps/vulnerable_app.py` | yes | 7% | authn 9, authz 16, injection 0, data 0, ops 0 | 0 / 6 / 6 / 0 |

## Agent trials

**None recorded yet.** The skill has not been measured on an agent. Until trials are run (protocol in `README.md`), nothing here says the skill improves agent output; it only shows the measuring tool works.

| Date | Model | Condition (skill version) | Score | Failed checks | Static scan | Report lists what is not covered? | Notes |
|---|---|---|---|---|---|---|---|
| | | | | | | | |
