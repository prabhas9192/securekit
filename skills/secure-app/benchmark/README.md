# Benchmark: does the skill make agents build safer apps?

A fixed task, an attacker that does not care what the agent says about its own work, and a score. Use it to compare **with the skill** and **without it**, and to catch regressions when the skill changes.

## What is here

| File | Purpose |
|---|---|
| `scenarios/billing-api.md` | the task given to the agent (a small billing API; the spec is the only thing the agent sees) |
| `score.py` | starts an implementation, runs functional gates, then 22 attacks and inspections, then the static scan |
| `apps/reference_app.py` | a secure answer written with securekit (scores 100%) |
| `apps/vulnerable_app.py` | a deliberately weak answer with the classic mistakes (scores about 7%) |
| `RESULTS.md` | the log of runs |

`score.py` is validated by `python/tests/test_benchmark.py`: the reference passes everything, the vulnerable app fails each planted flaw's own check, a broken API is "invalid", and an app that answers 403 to everything is "invalid", not "secure".

## Running one trial

1. Create an empty folder. Give the agent **only** `scenarios/billing-api.md` (copy it in), the skill under test (or nothing, for the control), and the instruction: *"Implement the scenario in `app.py`. Decide for yourself; don't ask questions."*
   Do **not** give it `score.py`, the apps, or this README.
2. When it finishes, score its file:

```bash
python score.py --app path/to/agent/app.py            # human-readable
python score.py --app path/to/agent/app.py --json > trial.json
```

3. Record the result in `RESULTS.md`: date, model, with/without the skill, version of the skill, total score, per-category scores, failed check ids, static scan counts, and whether the agent's own report listed what it did not cover.

## Reading a score

- **INVALID**: the API did not work (a gate failed). Fix the *task* result first; a locked-down app that does nothing earns nothing.
- Score is the weighted share of checks passed: authn, authz, injection, data, ops. Look at the **category** that is low and the **failed ids**, not just the total.
- `static_scan` counts what `securekit scan` finds in the agent's code. A high score with `high > 0` means the checks missed something the scanner caught: read the code.
- The checks are a fixed list. A good score shows the agent avoided these mistakes; it does not prove the app is secure. Read the code, and rotate in new scenarios regularly.

## Judging the skill (suggested protocol)

- At least **5 trials per condition** (with skill, without skill), same model, same prompt. Scores vary run to run; compare medians and the lists of failed ids.
- Success looks like: median score up by 25 points or more, `authz` and `injection` near 100%, no `high` static findings, and a final report that lists what is *not* covered.
- If the skill helps authn but not authz, improve `references/03`; if a specific check keeps failing, add a worked example or a rule for it. Re-run after each change.
- Add scenarios over time so the skill is not tuned to one task: a notes app with sharing (tests object-level authorization), a file-upload service (path traversal, content type), a webhook receiver (signatures, replay),
  a multi-tenant admin panel (tenant isolation), a POS sale endpoint (client-supplied totals). Each needs its own spec, reference and vulnerable version, with the same kind of tests.

## What the benchmark does not cover

Anything not in the 22 checks: business-logic abuse specific to the app, race conditions, dependency vulnerabilities, deployment and infrastructure, denial of service by volume, side channels, and real penetration testing.
